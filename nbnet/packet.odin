package nbnet
import "core:fmt"
import "core:math"
import "core:math/linalg"
import "core:mem"
import "core:os"
import "core:time"

PACKET_MAX_SIZE :: 1_024
MAX_MESSAGES_PER_PACKET :: 255

PACKET_HEADER_SIZE :: size_of(PacketHeader)
PACKET_MAX_DATA_SIZE :: (PACKET_MAX_SIZE - PACKET_HEADER_SIZE)

PACKET_MAX_USER_DATA_SIZE :: (PACKET_MAX_DATA_SIZE - AES_BLOCKLEN)

PacketStatus :: enum {
	Error = -1,
	Ok,
	NoSpace,
}

PacketMode :: enum {
	Write = 1,
	Read,
}

PacketHeader :: struct {
	protocol_id: u32,
	seq_number: u16,
	ack: u16,
	ack_bits: u32,
	message_count: u8,
	is_enc: u8,
	auth_tag: [POLY1305_TAGLEN]u8,
}

Packet :: struct {
	header: PacketHeader,
	mode: PacketMode,
	sender: ^Connection,
	buffer: [PACKET_MAX_SIZE]u8,
	size: uint,
	sealed: bool,

	w_stream: WriteStream,
	r_stream: ReadStream,
	m_stream: MeasureStream,

	aes_iv: [AES_BLOCKLEN]u8,
}

Packet_init_write :: proc(packet: ^Packet, protocol_id: u32, seq_number: u16, ack: u16, ack_bits: u32)
{
	packet.header.protocol_id = protocol_id
	packet.header.message_count = 0
	packet.header.seq_number = seq_number
	packet.header.ack = ack
	packet.header.ack_bits = ack_bits

	packet.mode = .Write
	packet.sender = nil
	packet.size = 0
	packet.sealed = false
	packet.m_stream.num_bits = 0

	WriteStream_init(&packet.w_stream, transmute([^]u8) mem.ptr_offset(&packet.buffer, PACKET_HEADER_SIZE), PACKET_MAX_USER_DATA_SIZE)
	MeasureStream_init(&packet.m_stream)
}

Packet_init_read :: proc(packet: ^Packet, sender: ^Connection, buffer: [PACKET_MAX_SIZE]u8, size: uint) -> (int)
{
	packet.mode = .Read
	packet.sender = sender
	packet.size = size
	packet.sealed = false

	buffer := buffer
	mem.copy(&packet.buffer, &buffer, int( size ))

	header_r_stream: ReadStream
	ReadStream_init(&header_r_stream, transmute([^]u8) &packet.buffer, PACKET_HEADER_SIZE)
	if Packet_serialize_header(&packet.header, cast(^Stream) &header_r_stream) < 0 {
		return ERROR
	}

	if sender.endpoint.config.is_enc_enabled && bool(packet.header.is_enc) {
		if !bool(sender.can_decrypt) {
			log(.Error, "Discard encrypted packet %d", packet.header.seq_number)
			return ERROR
		}

		Packet_compute_IV(packet, packet.sender)
		if !Packet_check_authentication(packet, packet.sender) {
			log(.Error, "Authentication check failed for packet %d", packet.header.seq_number)
			return ERROR
		}

		Packet_decrypt(packet, packet.sender)
	}

	ReadStream_init(&packet.r_stream, transmute([^]u8) mem.ptr_offset(&packet.buffer, PACKET_HEADER_SIZE), packet.size)
	return 0
}

Packet_read_protocol_id :: proc(buffer: [PACKET_MAX_SIZE]u8, size: uint) -> (int)
{
	if size < PACKET_HEADER_SIZE {
		return 0
	}

	buffer := buffer
	r_stream: ReadStream
	ReadStream_init(&r_stream, transmute([^]u8) &buffer, PACKET_HEADER_SIZE)

	header: PacketHeader
	if Packet_serialize_header(&header, cast(^Stream) &r_stream) < 0 {
		return 0
	}

	return cast(int) header.protocol_id
}

Packet_write_message :: proc(packet: ^Packet, message: ^Message, msg_s: MessageSerializer) -> (PacketStatus)
{
	if packet.mode != .Write || packet.sealed {
		return .Error
	}

	num_bits := int(packet.m_stream.num_bits)
	if Message_measure(message, &packet.m_stream, msg_s) < 0 {
		return .Error
	}

	if (packet.header.message_count >= MAX_MESSAGES_PER_PACKET ||
		packet.m_stream.num_bits > PACKET_MAX_USER_DATA_SIZE * 8) {
		packet.m_stream.num_bits = cast(uint) num_bits
		return .NoSpace
	}

	if Message_serialize_header(&message.header, cast(^Stream) &packet.w_stream) < 0 {
		return .Error
	}

	if Message_serialize_data(message, cast(^Stream) &packet.w_stream, msg_s) < 0 {
		return .Error
	}

	packet.size = (packet.m_stream.num_bits - 1) / 8 + 1
	packet.header.message_count += 1
	return .Ok
}

Packet_seal :: proc(packet: ^Packet, connection: ^Connection) -> (int)
{
	if packet.mode != .Write {
		return ERROR
	}

	if WriteStream_flush(&packet.w_stream) < 0 {
		return ERROR
	}

	is_enc := bool(bool(connection.endpoint.config.is_enc_enabled) && bool(connection.can_encrypt))

	packet.header.is_enc = u8( is_enc )
	packet.size += PACKET_HEADER_SIZE

	if is_enc {
		Packet_compute_IV(packet, connection)
		Packet_encrypt(packet, connection)
		Packet_authenticate(packet, connection)
	}

	hdr: WriteStream
	WriteStream_init(&hdr, transmute([^]u8) &packet.buffer, PACKET_HEADER_SIZE)
	if Packet_serialize_header(&packet.header, cast(^Stream) &hdr) < 0 {
		return ERROR
	}

	if WriteStream_flush(&hdr) < 0 {
		return ERROR
	}

	packet.sealed = true
	return 0
}

@private
Packet_serialize_header :: proc(header: ^PacketHeader, stream: ^Stream) -> (int)
{
	serialize_bytes(stream, &header.protocol_id, size_of(header.protocol_id))
	serialize_bytes(stream, &header.seq_number, size_of(header.seq_number))
	serialize_bytes(stream, &header.ack, size_of(header.ack))
	serialize_bytes(stream, &header.ack_bits, size_of(header.ack_bits))
	serialize_bytes(stream, &header.message_count, size_of(header.message_count))
	serialize_bytes(stream, &header.is_enc, size_of(header.is_enc))

	if bool(header.is_enc) {
		serialize_bytes(stream, DEMOTE(&header.auth_tag), size_of(header.auth_tag))
	}

	return 0
}

Packet_encrypt :: proc(packet: ^Packet, connection: ^Connection)
{
	aes: AESCtx
	AES_init_ctx_iv(&aes, DEMOTE(&connection.keys1.shared_key), DEMOTE(&packet.aes_iv))

	bytes_to_enc := uint(packet.size - PACKET_HEADER_SIZE)
	added_bytes := uint(0 if (bytes_to_enc % AES_BLOCKLEN == 0) else (AES_BLOCKLEN - bytes_to_enc % AES_BLOCKLEN))

	bytes_to_enc += added_bytes

	assert(bytes_to_enc % AES_BLOCKLEN == 0)
	assert(bytes_to_enc < PACKET_MAX_DATA_SIZE)

	packet.size = PACKET_HEADER_SIZE + bytes_to_enc

	assert(packet.size < PACKET_MAX_SIZE)

	mem.set(mem.ptr_offset(transmute([^]u8) &packet.buffer, packet.size - added_bytes), 0, int( added_bytes ))
	AES_CBC_encrypt_buffer(&aes, mem.ptr_offset( transmute([^]u8) &packet.buffer, PACKET_HEADER_SIZE ), u32(bytes_to_enc))

	log(.Trace, "Encrypted packet %d (%d bytes)", packet.header.seq_number, packet.size)
}

Packet_decrypt :: proc(packet: ^Packet, connection: ^Connection)
{
	aes: AESCtx
	AES_init_ctx_iv(&aes, DEMOTE(&connection.keys1.shared_key), DEMOTE(&packet.aes_iv))
	bytes_to_dec := uint(packet.size - PACKET_HEADER_SIZE)

	assert(bytes_to_dec % AES_BLOCKLEN == 0)
	assert(bytes_to_dec < PACKET_MAX_DATA_SIZE)

	AES_CBC_decrypt_buffer(&aes, mem.ptr_offset(transmute([^]u8) &packet.buffer, PACKET_HEADER_SIZE), u32(bytes_to_dec))

	log(.Trace, "Decrypted packet %d (%d bytes)", packet.header.seq_number, packet.size)
}

Packet_compute_IV :: proc(packet: ^Packet, connection: ^Connection)
{
	aes: AESCtx
	AES_init_ctx_iv(&aes, DEMOTE(&connection.keys2.shared_key), DEMOTE(&connection.aes_iv))

	mem.set(DEMOTE(&packet.aes_iv), 0, AES_BLOCKLEN)
	mem.copy(DEMOTE(&packet.aes_iv), cast(^u8) &packet.header.seq_number, size_of(packet.header.seq_number))

	AES_CBC_encrypt_buffer(&aes, DEMOTE(&packet.aes_iv), AES_BLOCKLEN)
}

Packet_authenticate :: proc(packet: ^Packet, connection: ^Connection)
{
	poly1305_key := [POLY1305_KEYLEN]u8{}

	Packet_compute_poly1305_key(packet, connection, DEMOTE(&poly1305_key))

	mem.zero(DEMOTE(&packet.header.auth_tag), POLY1305_TAGLEN)

	d_packet_buf := DEMOTE(&packet.buffer)
	poly1305_auth(&packet.header.auth_tag,
		transmute(type_of(d_packet_buf)) mem.ptr_offset(d_packet_buf, PACKET_HEADER_SIZE),
		packet.size + PACKET_HEADER_SIZE,
		(&poly1305_key))
}

Packet_check_authentication :: proc(packet: ^Packet, connection: ^Connection) -> (bool)
{
	poly1305_key := [POLY1305_KEYLEN]u8{}
	auth_tag := [POLY1305_TAGLEN]u8{}

	Packet_compute_poly1305_key(packet, connection, DEMOTE(&poly1305_key))

	d_packet_buf := DEMOTE(&packet.buffer)
	poly1305_auth((&auth_tag),
		transmute(type_of(d_packet_buf)) mem.ptr_offset(d_packet_buf, PACKET_HEADER_SIZE),
		packet.size - PACKET_HEADER_SIZE,
		(&poly1305_key))

	return mem.compare_byte_ptrs(DEMOTE(&packet.header.auth_tag), DEMOTE(&auth_tag), POLY1305_TAGLEN) == 0
}

Packet_compute_poly1305_key :: proc(packet: ^Packet, connection: ^Connection, poly1305_key: [^]u8)
{
	aes_ctx := AESCtx{}

	mem.copy(poly1305_key, transmute([^]u8) &packet.header.seq_number, size_of(packet.header.seq_number))

	AES_init_ctx_iv(&aes_ctx, DEMOTE(&connection.keys3.shared_key), DEMOTE(&connection.aes_iv))
	AES_CBC_encrypt_buffer(&aes_ctx, poly1305_key, POLY1305_KEYLEN)
}