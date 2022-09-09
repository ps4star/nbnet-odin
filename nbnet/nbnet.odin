package nbnet
import "core:fmt"
import "core:math"
import "core:math/linalg"
import "core:mem"
import "core:os"
import "core:time"

// Some Odin compat stuff
TimeT :: time.Time
FileT :: os.Handle

// Logging mechanism
@(private="package")
LogLevel :: enum {
	Info,
	Trace,
	Debug,
	Error,
}

@private LogEntry :: struct {
	level: LogLevel,
	msg: string,
}

@private g_logs: [dynamic]LogEntry

@(private="package")
log :: proc(level: LogLevel, fmt_s: string, args: ..any)
{
	out_str := fmt.aprintf(fmt_s, args)
	append(&g_logs, LogEntry{ level = level, msg = out_str })
	fmt.printf("%s\n", out_str)
}

// Fixed array -> ptr demotion (C-style)
// i.e. (^)[N]T -> [^]T
DEMOTE :: #force_inline proc(arr: ^[$N]$T, idx: int = 0) -> ([^]T)
	where N > 0
{
	return transmute([^]T) &(arr^[idx])
}

// PORT BEGIN
// (no region set)
allocator :: mem.alloc
reallocator :: #force_inline proc(ptr: rawptr, size: int, old_size := 1)
{
	mem.resize(ptr, old_size, size)
}
deallocator :: mem.free

// region Declarations
abort :: proc()
{

}

ERROR :: -1

ConnectionVector :: struct {
	connections: [dynamic]Connection,
	//count, capacity: uint,
}

// region MemoryManagement
MemType :: enum {
	MsgChunk,
	ByteArrayMsg,
	Connection,
}

MemPoolFreeBlock :: struct {
	next: ^MemPoolFreeBlock,
}

MemPool :: struct {
	blocks: [^]^u8,
	block_size: uint,
	block_count: uint,
	block_idx: uint,
	free: ^MemPoolFreeBlock,
}

MemoryManager :: struct {
	mem_pools: [16]MemPool,
}

// region Serialization
Word :: u32

WORD_BYTES :: size_of(Word)
WORD_BITS :: (WORD_BYTES * 8)

BITS_REQUIRED :: #force_inline proc(min, max: $T) -> (T)
{
	return 0 if (min == max) else get_required_number_of_bits_for(max - min)
}

B_MASK :: #force_inline proc(n: uint) -> (uint) { return (1 << n) }
B_SET :: #force_inline proc(mask: ^$T, n: uint) { mask^ |= B_MASK(n) }
B_UNSET :: #force_inline proc(mask: ^$T, n: uint) { mask^ &= ~B_MASK(n) }
B_IS_SET :: #force_inline proc(mask: $T, n: uint) { return (B_MASK(n) & mask) == B_MASK(n) }
B_IS_UNSET :: #force_inline proc(mask: $T, n: uint) { return (B_MASK(n) & mask) == 0 }

ASSERT_VALUE_IN_RANGE :: #force_inline proc(v, min, max: $T) { assert(v >= min && v <= max) }
ASSERTED_SERIALIZE :: #force_inline proc(stream: ^Stream, v, min, max: $T, val_to_compare: $T2)
{
	if stream.type == .Write {
		ASSERT_VALUE_IN_RANGE(v, min, max)
	}

	if val_to_compare < 0 {
		abort()
	}

	if stream.type == .Read {
		ASSERT_VALUE_IN_RANGE(v, min, max)
	}
}

serialize_uint :: #force_inline proc(stream: ^Stream, v, min, max: $T)
{
	ASSERTED_SERIALIZE(stream, v, min, max, stream->serialize_uint_func(transmute(^uint) &(v), min, max))
}

serialize_int :: #force_inline proc(stream: ^Stream, v, min, max: $T)
{
	ASSERTED_SERIALIZE(stream, v, min, max, stream->serialize_int_func(&v, min, max))
}

serialize_float :: #force_inline proc(stream: ^Stream, v, min, max: $T, precision: f32)
{
	ASSERTED_SERIALIZE(stream, v, min, max, stream->serialize_float_func(&v, min, max, precision))
}

serialize_bool :: #force_inline proc(stream: ^Stream, v: $T)
{
	ASSERTED_SERIALIZE(stream, v, 0, 1, stream->serialize_bool_func( &(v) ))
}

serialize_string :: #force_inline proc(stream: ^Stream, v: string, length: $T)
{
	serialize_bytes(stream, v, length)
}

serialize_bytes :: #force_inline proc(stream: ^Stream, v: $T1, length: $T2)
{
	stream->serialize_bytes_func(transmute([^]u8) v, uint(length))
}

serialize_padding :: #force_inline proc(stream: ^Stream)
{
	stream->serialize_padding_func()
}

// region BitReader
BitReader :: struct {
	size: uint,
	buffer: [^]u8,
	scratch: u64,
	scratch_bits_count: uint,
	byte_cursor: uint,
}

BitReader_init :: proc(br: ^BitReader, buffer: [^]u8, size: uint)
{
	br.size = size
	br.buffer = buffer
	br.scratch = 0
	br.scratch_bits_count = 0
	br.byte_cursor = 0
}

BitReader_read :: proc(br: ^BitReader, word: ^Word, num_bits: uint) -> (int)
{
	word^ = 0
	if num_bits > br.scratch_bits_count {
		needed: uint = (num_bits - br.scratch_bits_count - 1) / 8 + 1
		if br.byte_cursor + needed > br.size {
			return ERROR
		}

		BitReader_read_from_buffer(br)
	}

	word^ |= u32(br.scratch & ((u64(1) << num_bits) - 1))
	br.scratch >>= num_bits
	br.scratch_bits_count -= num_bits

	return 0
}

@private
BitReader_read_from_buffer :: proc(br: ^BitReader)
{
	bytes_count: uint = MIN(br.size - br.byte_cursor, WORD_BYTES)
	word: Word = 0

	mem.copy(&word, mem.ptr_offset(br.buffer, br.byte_cursor), int( bytes_count ))

	br.scratch |= u64(word) << br.scratch_bits_count
	br.scratch_bits_count += bytes_count * 8
	br.byte_cursor += bytes_count
}

// region BitWriter
BitWriter :: struct {
	size: uint,
	buffer: [^]u8,
	scratch: u64,
	scratch_bits_count: uint,
	byte_cursor: uint,
}

BitWriter_init :: proc(bw: ^BitWriter, buffer: [^]u8, size: uint)
{
	bw.size = size
	bw.buffer = buffer
	bw.scratch = 0
	bw.scratch_bits_count = 0
	bw.byte_cursor = 0
}

BitWriter_write :: proc(bw: ^BitWriter, value: Word, num_bits: uint) -> (int)
{
	bw.scratch |= (u64(value) << bw.scratch_bits_count)

	if bw.scratch_bits_count += num_bits; bw.scratch_bits_count >= WORD_BITS {
		return BitWriter_flush_scratch_bits(bw, WORD_BITS)
	}

	return 0
}

BitWriter_flush :: proc(bw: ^BitWriter) -> (int)
{
	return BitWriter_flush_scratch_bits(bw, bw.scratch_bits_count)
}

@private
BitWriter_flush_scratch_bits :: proc(bw: ^BitWriter, num_bits: uint) -> (int)
{
	if bw.scratch_bits_count < 1 {
		return 0
	}

	bytes_count: uint = (num_bits - 1) / 8 + 1
	assert(bytes_count <= WORD_BYTES)

	if (bw.byte_cursor + bytes_count) > bw.size {
		return ERROR
	}

	word := Word(0 | (bw.scratch & ((u64(1) << num_bits) - 1)))

	mem.copy(mem.ptr_offset(bw.buffer, bw.byte_cursor), &word, int( bytes_count ))

	bw.scratch >>= num_bits
	bw.scratch_bits_count -= num_bits
	bw.byte_cursor += bytes_count

	return 0
}

// region Stream
Stream_serialize_uint		:: #type proc(^Stream, ^uint, uint, uint)		-> (int)
Stream_serialize_int		:: #type proc(^Stream, ^int, int, int)			-> (int)
Stream_serialize_float		:: #type proc(^Stream, ^f32, f32, f32, int)		-> (int)
Stream_serialize_bool		:: #type proc(^Stream, ^bool)					-> (int)
Stream_serialize_padding	:: #type proc(^Stream)							-> (int)
Stream_serialize_bytes		:: #type proc(^Stream, ^u8, uint)				-> (int)

StreamType :: enum {
	Write,
	Read,
	Measure,
}

Stream :: struct {
	type: StreamType,
	serialize_uint_func:		Stream_serialize_uint,
	serialize_int_func:			Stream_serialize_int,
	serialize_float_func:		Stream_serialize_float,
	serialize_bool_func:		Stream_serialize_bool,
	serialize_padding_func:		Stream_serialize_padding,
	serialize_bytes_func:		Stream_serialize_bytes,
}

// region ReadStream
ReadStream :: struct {
	using base: Stream,
	br: BitReader,
}

ReadStream_init :: proc(rs: ^ReadStream, buffer: [^]u8, size: uint)
{
	rs.base.type = .Read
	rs.base.serialize_uint_func = cast(Stream_serialize_uint) ReadStream_serialize_uint
	rs.base.serialize_int_func = cast(Stream_serialize_int) ReadStream_serialize_int
	rs.base.serialize_float_func = cast(Stream_serialize_float) ReadStream_serialize_float
	rs.base.serialize_bool_func = cast(Stream_serialize_bool) ReadStream_serialize_bool
	rs.base.serialize_padding_func = cast(Stream_serialize_padding) ReadStream_serialize_padding
	rs.base.serialize_bytes_func = cast(Stream_serialize_bytes) ReadStream_serialize_bytes

	BitReader_init(&rs.br, buffer, size)
}

ReadStream_serialize_uint :: proc(rs: ^ReadStream, value: ^uint, min, max: uint) -> (int)
{
	assert(min <= max)

	if BitReader_read(&rs.br, transmute(^Word) value, BITS_REQUIRED(min, max)) < 0 {
		return ERROR
	}

	value^ += min

	if value^ < min || value^ > max {
		return ERROR
	}

	return 0
}

ReadStream_serialize_int :: proc(rs: ^ReadStream, value: ^int, min, max: int) -> (int)
{
	assert(min <= max)

	is_negative: bool = false
	abs_min := cast(uint) MIN(abs(min), abs(max))
	abs_max := cast(uint) MAX(abs(min), abs(max))

	is_negative = value^ < 0 // TODO: useless, remove this?
	value^ = abs(value^)

	if ReadStream_serialize_bool(rs, &is_negative) < 0 {
		return ERROR
	}

	if ReadStream_serialize_uint(rs, transmute(^uint) value, 0 if (min < 0 && max > 0) else abs_min, abs_max) < 0 {
		return ERROR
	}

	if is_negative {
		value^ *= -1
	}

	return 0
}

ReadStream_serialize_float :: proc(rs: ^ReadStream, value: ^f32, min, max: f32, precision: int) -> (int)
{
    assert(min <= max)

    mult := cast(uint) math.pow_f32(f32(10), f32(precision))
    i_min := int(min * f32(mult))
    i_max := int(max * f32(mult))
    i_val: int

    if ReadStream_serialize_int(rs, &i_val, i_min, i_max) < 0 {
    	return ERROR
    }

    value^ = f32(i_val) / f32(mult)
    return 0
}

ReadStream_serialize_bool :: proc(rs: ^ReadStream, value: ^bool) -> (int)
{
	v: Word

	if BitReader_read(&rs.br, &v, 1) < 0 {
		return ERROR
	}

	if v < 0 || v > 1 {
		return ERROR
	}

	value^ = bool(v)
	return 0
}

ReadStream_serialize_padding :: proc(rs: ^ReadStream) -> (int)
{
	if rs.br.scratch_bits_count % 8 == 0 {
		return 0
	}

	value: Word
	padding := uint(rs.br.scratch_bits_count % 8)
	ret := int(BitReader_read(&rs.br, &value, padding))

	if value != 0 {
		return ERROR
	}

	return ret
}

ReadStream_serialize_bytes :: proc(rs: ^ReadStream, bytes: [^]u8, length: uint) -> (int)
{
	if length == 0 {
		return ERROR
	}

	if ReadStream_serialize_padding(rs) < 0 {
		return ERROR
	}

	br := &rs.br

	assert(br.scratch_bits_count % 8 == 0)
	if length * 8 <= br.scratch_bits_count {
		word: Word
		if BitReader_read(br, &word, length * 8) < 0 {
			return ERROR
		}

		mem.copy(bytes, &word, int( length ))
	} else {
		br.byte_cursor -= (br.scratch_bits_count / 8)
		br.scratch_bits_count = 0
		br.scratch = 0

		mem.copy(bytes, mem.ptr_offset(br.buffer, br.byte_cursor), int(length))

		br.byte_cursor += length
	}

	return 0
}

// region WriteStream
WriteStream :: struct {
	using base: Stream,
	bw: BitWriter,
}

WriteStream_init :: proc(ws: ^WriteStream, buffer: [^]u8, size: uint)
{
	ws.base.type = .Write
	ws.base.serialize_uint_func = cast(Stream_serialize_uint) WriteStream_serialize_uint
	ws.base.serialize_int_func = cast(Stream_serialize_int) WriteStream_serialize_int
	ws.base.serialize_float_func = cast(Stream_serialize_float) WriteStream_serialize_float
	ws.base.serialize_bool_func = cast(Stream_serialize_bool) WriteStream_serialize_bool
	ws.base.serialize_padding_func = cast(Stream_serialize_padding) WriteStream_serialize_padding
	ws.base.serialize_bytes_func = cast(Stream_serialize_bytes) WriteStream_serialize_bytes

	BitWriter_init(&ws.bw, buffer, size)
}

WriteStream_serialize_uint :: proc(ws: ^WriteStream, value: ^uint, min, max: uint) -> (int)
{
	assert(min <= max)
	assert(value^ >= min && value^ <= max)

	if BitWriter_write(&ws.bw, Word(value^ - min), BITS_REQUIRED(min, max)) < 0 {
		return ERROR
	}

	return 0
}

WriteStream_serialize_int :: proc(ws: ^WriteStream, value: ^int, min, max: int) -> (int)
{
	assert(min <= max)

	is_negative: bool = false
	abs_min := cast(uint) MIN(abs(min), abs(max))
	abs_max := cast(uint) MAX(abs(min), abs(max))

	is_negative = value^ < 0 // TODO: useless, remove this?
	value^ = abs(value^)

	if WriteStream_serialize_uint(ws, transmute(^uint) &is_negative, 0, 1) < 0 {
		return ERROR
	}

	if WriteStream_serialize_uint(ws, transmute(^uint) value, 0 if (min < 0 && max > 0) else abs_min, abs_max) < 0 {
		return ERROR
	}

	if is_negative {
		value^ *= -1
	}

	return 0
}

WriteStream_serialize_float :: proc(ws: ^WriteStream, value: ^f32, min, max: f32, precision: int) -> (int)
{
    assert(min <= max)

    mult: uint = cast(uint) math.pow_f32(f32(10), f32(precision))
    i_min := int(min * f32(mult))
    i_max := int(max * f32(mult))
    i_val: int

    if WriteStream_serialize_int(ws, &i_val, i_min, i_max) < 0 {
    	return ERROR
    }

    return 0
}

WriteStream_serialize_bool :: proc(ws: ^WriteStream, value: ^bool) -> (int)
{
	v := int(value^)

	assert(v >= 0 && v <= 1)

	if BitWriter_write(&ws.bw, cast(Word) v, 1) < 0 {
		return ERROR
	}

	return 0
}

WriteStream_serialize_padding :: proc(ws: ^WriteStream) -> (int)
{
	if ws.bw.scratch_bits_count % 8 == 0 {
		return 0
	}

	padding := uint(8 - (ws.bw.scratch_bits_count % 8))
	return BitWriter_write(&ws.bw, 0, padding)
}

WriteStream_serialize_bytes :: proc(ws: ^WriteStream, bytes: [^]u8, length: uint) -> (int)
{
	if length == 0 {
		return ERROR
	}

	if WriteStream_serialize_padding(ws) < 0 {
		return ERROR
	}

	bw := &ws.bw

	assert(bw.scratch_bits_count % 8 == 0)
	if WriteStream_flush(ws) < 0 {
		return ERROR
	}

	assert(bw.scratch_bits_count == 0)

	if bw.byte_cursor + length > bw.size {
		return ERROR
	}

	mem.copy(mem.ptr_offset(bw.buffer, bw.byte_cursor), bytes, int(length))

	return 0
}

WriteStream_flush :: proc(ws: ^WriteStream) -> (int)
{
	return BitWriter_flush(&ws.bw)
}

// region MeasureStream
MeasureStream :: struct {
	using base: Stream,
	num_bits: uint,
}

MeasureStream_init :: proc(ms: ^MeasureStream)
{
	ms.base.type = .Measure
	ms.base.serialize_uint_func = cast(Stream_serialize_uint) WriteStream_serialize_uint
	ms.base.serialize_int_func = cast(Stream_serialize_int) WriteStream_serialize_int
	ms.base.serialize_float_func = cast(Stream_serialize_float) WriteStream_serialize_float
	ms.base.serialize_bool_func = cast(Stream_serialize_bool) WriteStream_serialize_bool
	ms.base.serialize_padding_func = cast(Stream_serialize_padding) WriteStream_serialize_padding
	ms.base.serialize_bytes_func = cast(Stream_serialize_bytes) WriteStream_serialize_bytes

	ms.num_bits = 0
}

MeasureStream_serialize_uint :: proc(ms: ^MeasureStream, value: ^uint, min, max: uint) -> (int)
{
	assert(min <= max)

	num_bits: uint = BITS_REQUIRED(min, max)
	ms.num_bits += num_bits
	return int(num_bits)
}

MeasureStream_serialize_int :: proc(ms: ^MeasureStream, value: ^int, min, max: int) -> (int)
{
	assert(min <= max)
	assert(value^ >= min && value^ <= max)

	abs_min := cast(uint) MIN(abs(min), abs(max))
	abs_max := cast(uint) MAX(abs(min), abs(max))
	abs_value := cast(uint) abs(value^)

	num_bits := uint(MeasureStream_serialize_uint(ms, &abs_value, 0 if (min < 0 && max > 0) else abs_min, abs_max))

	ms.num_bits += 1
	return int(num_bits + 1)
}

MeasureStream_serialize_float :: proc(ms: ^MeasureStream, value: ^f32, min, max: f32, precision: int) -> (int)
{
	assert(min <= max)
	assert(value^ >= min && value^ <= max)

	mult := uint(math.pow_f32(f32(10), f32(precision)))
	i_min := int(min * f32(mult))
	i_max := int(max * f32(mult))
	i_val := int(value^ * f32(mult))

	return MeasureStream_serialize_int(ms, &i_val, i_min, i_max)
}

MeasureStream_serialize_bool :: proc(ms: ^MeasureStream, value: ^bool) -> (int)
{
	ms.num_bits += 1
	return 1
}

MeasureStream_serialize_padding :: proc(ms: ^MeasureStream) -> (int)
{
	if ms.num_bits % 8 == 0 {
		return 0
	}

	padding := uint(8 - (ms.num_bits % 8))
	ms.num_bits += padding
	return cast(int) padding
}

MeasureStream_serialize_bytes :: proc(ms: ^MeasureStream, bytes: [^]u8, length: uint) -> (int)
{
	MeasureStream_serialize_padding(ms)
	bits := uint(length * 8)
	ms.num_bits += bits
	return cast(int) bits
}

MeasureStream_reset :: proc(ms: ^MeasureStream)
{
	ms.num_bits = 0
}

// region Message
MAX_CHANNELS :: 32
MAX_MESSAGE_TYPES :: 255
MESSAGE_RESEND_DELAY :: 0.1

MessageSerializer 		:: #type proc(rawptr, ^Stream) -> (int)
MessageBuilder 			:: #type proc() -> (rawptr)
MessageDestructor		:: #type proc(rawptr)

MessageHeader :: struct {
	id: u16,
	type: u8,
	channel_id: u8,
}

OutgoingMessage :: struct {
	type: u8,
	ref_count: uint,
	data: rawptr,
}

Message :: struct {
	using header: MessageHeader,
	sender: ^Connection,
	outgoing_msg: ^OutgoingMessage,
	data: rawptr,
}

MessageInfo :: struct {
	type: u8,
	data: rawptr,
	sender: ^Connection,
}

Message_serialize_header :: proc(mh: ^MessageHeader, stream: ^Stream) -> (int)
{
  serialize_bytes(stream, &mh.id, size_of(mh.id))
  serialize_bytes(stream, &mh.type, size_of(mh.type))
  serialize_bytes(stream, &mh.channel_id, size_of(mh.channel_id))

  return 0
}

Message_measure :: proc(msg: ^Message, m_stream: ^MeasureStream, msg_s: MessageSerializer) -> (int)
{
    if Message_serialize_header(&msg.header, cast(^Stream) m_stream) < 0 {
    	return ERROR
    }

    if Message_serialize_data(msg, cast(^Stream) m_stream, msg_s) < 0 {
    	return ERROR
    }

    return cast(int) m_stream.num_bits
}

Message_serialize_data :: proc(msg: ^Message, stream: ^Stream, msg_s: MessageSerializer) -> (int)
{
	return msg_s(msg.data, stream)
}

// region Encryption
// region ECDH
NIST_B163 :: 1
NIST_K163 :: 2
NIST_B233 :: 3
NIST_K233 :: 4
NIST_B283 :: 5
NIST_K283 :: 6
NIST_B409 :: 7
NIST_K409 :: 8
NIST_B571 :: 9
NIST_K571 :: 10

ECC_CURVE :: NIST_B233

when (ECC_CURVE > -1 && ECC_CURVE != 0) {
	when (ECC_CURVE == NIST_K163) || (ECC_CURVE == NIST_B163) {
		CURVE_DEGREE 		:: 163
		ECC_PRV_KEY_SIZE 	:: 24
	} else when (ECC_CURVE == NIST_K233) || (ECC_CURVE == NIST_B233) {
		CURVE_DEGREE		:: 233
		ECC_PRV_KEY_SIZE	:: 32
	} else when (ECC_CURVE == NIST_K283) || (ECC_CURVE == NIST_B283) {
		CURVE_DEGREE		:: 283
		ECC_PRV_KEY_SIZE	:: 36
	} else when (ECC_CURVE == NIST_K409) || (ECC_CURVE == NIST_B409) {
		CURVE_DEGREE		:: 409
		ECC_PRV_KEY_SIZE	:: 52
	} else when (ECC_CURVE == NIST_K571) || (ECC_CURVE == NIST_B571) {
		CURVE_DEGREE		:: 571
		ECC_PRV_KEY_SIZE	:: 72
	}
} else {
	#panic("Must define a curve to use.")
}

ECC_PUB_KEY_SIZE :: (2 * ECC_PRV_KEY_SIZE)

// region AES
AES128 :: 1
AES192 :: #config(AES192, -1)
AES256 :: #config(AES256, -1)

AES_BLOCKLEN :: 16

when (AES256 > -1 && AES256 == 1) {
    AES_KEYLEN		:: 32
    AES_keyExpSize	:: 240
} else when (AES192 > -1 && AES192 == 1) {
    AES_KEYLEN		:: 24
    AES_keyExpSize	:: 208
} else {
    AES_KEYLEN		:: 16   // Key length in bytes
    AES_keyExpSize	:: 176
}

AESCtx :: struct {
	round_key: [AES_keyExpSize]u8,
	iv: [AES_BLOCKLEN]u8,
}

// region Poly1305
POLY1305_KEYLEN :: 32
POLY1305_TAGLEN :: 16

// region PRNG
CSPRNG :: rawptr

CSPRNG_TYPE :: struct #raw_union {
	object: CSPRNG,
	urandom: FileT, // *FILE
}

// region Packet
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
		serialize_bytes(stream, &header.auth_tag, size_of(header.auth_tag))
	}

	return 0
}

Packet_encrypt :: proc(packet: ^Packet, connection: ^Connection)
{
	aes: AESCtx
	AES_init_ctx_iv(&aes, connection.keys1.shared_key, packet.aes_iv)

	bytes_to_enc := uint(packet.size - PACKET_HEADER_SIZE)
	added_bytes := uint(0 if (bytes_to_enc % AES_BLOCKLEN == 0) else (AES_BLOCKLEN - bytes_to_enc % AES_BLOCKLEN))

	bytes_to_enc += added_bytes

	assert(bytes_to_enc % AES_BLOCKLEN == 0)
	assert(bytes_to_enc < PACKET_MAX_DATA_SIZE)

	packet.size = PACKET_HEADER_SIZE + bytes_to_enc

	assert(packet.size < PACKET_MAX_SIZE)

	mem.set(mem.ptr_offset(transmute([^]u8) &packet.buffer, packet.size - added_bytes), 0, int( added_bytes ))
	AES_CBC_encrypt_buffer(&aes, mem.ptr_offset( transmute([^]u8) &packet.buffer, PACKET_HEADER_SIZE ), bytes_to_enc)

	log(.Trace, "Encrypted packet %d (%d bytes)", packet.header.seq_number, packet.size)
}

Packet_decrypt :: proc(packet: ^Packet, connection: ^Connection)
{
	aes: AESCtx
	AES_init_ctx_iv(&aes, connection.keys1.shared_key, packet.aes_iv)
	bytes_to_dec := uint(packet.size - PACKET_HEADER_SIZE)

	assert(bytes_to_dec % AES_BLOCKLEN == 0)
	assert(bytes_to_dec < PACKET_MAX_DATA_SIZE)

	AES_CBC_decrypt_buffer(&aes, mem.ptr_offset(transmute([^]u8) &packet.buffer, PACKET_HEADER_SIZE), bytes_to_dec)

	log(.Trace, "Decrypted packet %d (%d bytes)", packet.header.seq_number, packet.size)
}

Packet_compute_IV :: proc(packet: ^Packet, connection: ^Connection)
{
	aes: AESCtx
	AES_init_ctx_iv(&aes, connection.keys2.shared_key, connection.aes_iv)

	mem.set(DEMOTE(&packet.aes_iv), 0, AES_BLOCKLEN)
	mem.copy(DEMOTE(&packet.aes_iv), cast(^u8) &packet.header.seq_number, size_of(packet.header.seq_number))

	AES_CBC_encrypt_buffer(&aes, packet.aes_iv, AES_BLOCKLEN)
}


















// region MessageChunk
MESSAGE_CHUNK_SIZE :: (PACKET_MAX_USER_DATA_SIZE - size_of(MessageHeader) - 2)
MESSAGE_CHUNK_TYPE :: (MAX_MESSAGE_TYPES - 1)

MessageChunk :: struct {
	id: u8,
	total: u8,
	data: [MESSAGE_CHUNK_SIZE]u8,
	outgoing_msg: ^OutgoingMessage,
}

// region ClientClosedMessage
CLIENT_CLOSED_MESSAGE_TYPE :: (MAX_MESSAGE_TYPES - 2)

ClientClosedMessage :: struct {
	code: int,
}

// region ClientAcceptedMessage
CLIENT_ACCEPTED_MESSAGE_TYPE :: (MAX_MESSAGE_TYPES - 3)
ACCEPT_DATA_MAX_SIZE :: 4_096
CONNECTION_DATA_MAX_SIZE :: 512

ClientAcceptedMessage :: struct {
	data: [ACCEPT_DATA_MAX_SIZE]u8,
}

// region ByteArrayMessage
BYTE_ARRAY_MESSAGE_TYPE :: (MAX_MESSAGE_TYPES - 4)
BYTE_ARRAY_MAX_SIZE :: 4_096

ByteArrayMessage :: struct {
	bytes: [BYTE_ARRAY_MAX_SIZE]u8,
	length: uint,
}

// region PublicCryptoInfoMessage
PUBLIC_CRYPTO_INFO_MESSAGE_TYPE :: (MAX_MESSAGE_TYPES - 5)

PublicCryptoInfoMessage :: struct {
	pub_key1: [ECC_PUB_KEY_SIZE]u8,
	pub_key2: [ECC_PUB_KEY_SIZE]u8,
	pub_key3: [ECC_PUB_KEY_SIZE]u8,
	aes_iv: [AES_BLOCKLEN]u8,
}

// region StartEncryptMessage
START_ENCRYPT_MESSAGE_TYPE :: (MAX_MESSAGE_TYPES - 6)

// region DisconnectionMessage
DISCONNECTION_MESSAGE_TYPE :: (MAX_MESSAGE_TYPES - 7)

// region PublicCryptoInfoMessage
CONNECTION_REQUEST_MESSAGE_TYPE :: (MAX_MESSAGE_TYPES - 8)

ConnectionRequestMessage :: struct {
	data: [CONNECTION_DATA_MAX_SIZE]u8,
}

// region Channel
CHANNEL_BUFFER_SIZE :: 1_024
CHANNEL_CHUNKS_BUFFER_SIZE :: 255
CHANNEL_RW_CHUNK_BUFFER_INITIAL_SIZE :: 2_048

CHANNEL_RESERVED_UNRELIABLE :: (MAX_CHANNELS - 1)
CHANNEL_RESERVED_RELIABLE :: (MAX_CHANNELS - 2)
CHANNEL_RESERVED_LIBRARY_MESSAGES :: (MAX_CHANNELS - 3)

ChannelType :: enum {
	Undefined = -1,
	UnreliableOrdered,
	ReliableOrdered,
}

MessageSlot :: struct {
	message: Message,
	last_send_time: TimeT,
	free: bool,
}

Channel :: struct {
	id: u8,
	type: ChannelType,
	connection: ^Connection,
	next_outgoing_message_id: u16,
	next_recv_message_id: u16,
	outgoing_message_count: uint,
	chunk_count: uint,
	last_received_chunk_id: int,
	time: TimeT,
	write_chunk_buffer: ^u8,
	read_chunk_buffer: ^u8,
	write_chunk_buffer_size: uint,
	read_chunk_buffer_size: uint,
	next_outgoing_chunked_message: uint,
	outgoing_message_slot_buffer: [CHANNEL_BUFFER_SIZE]MessageSlot,
	recved_message_slot_buffer: [CHANNEL_BUFFER_SIZE]MessageSlot,
	recv_chunk_buffer: [CHANNEL_CHUNKS_BUFFER_SIZE]^MessageChunk,

	add_received_message: proc(^Channel, ^Message) -> (bool),
	add_outgoing_message: proc(^Channel, ^Message) -> (bool),
	get_next_recved_message: proc(^Channel) -> (^Message),
	get_next_outgoing_message: proc(^Channel) -> (^Message),
	on_outgoing_message_acked: proc(^Channel, u16) -> (int),
}

UnreliableOrderedChannel :: struct {
	using base: Channel,
	last_received_message_id: u16,
	next_ougoing_message_slot: uint,
}

ReliableOrderedChannel :: struct {
	using base: Channel,
	oldest_unacked_message_id: u16,
	most_recent_message_id: u16,
	ack_buffer: [CHANNEL_BUFFER_SIZE]bool,
}

// region Config
Config :: struct {
	protocol_name: string,
	ip_address: string,
	port: u16,
	is_enc_enabled: bool,
}

// region Connection
MAX_PACKET_ENTRIES :: 1_024
CONNECTION_MAX_SENT_PACKET_COUNT :: 16
CONNECTION_STALE_TIME_THRESHOLD :: 3

MessageEntry :: struct {
	id: u16,
	channel_id: u8,
}

PacketEntry :: struct {
	acked: bool,
	message_count: uint,
	send_time: TimeT,
	messages: [MAX_MESSAGES_PER_PACKET]MessageEntry,
}

ConnectionStats :: struct {
	ping: TimeT, // TODO: may need a type change
	packet_loss: f32,
	upload_bandwidth: f32,
	download_bandwidth: f32,
}

when DEBUG == YES {
	ConnectionDebugCallback :: enum {
		MsgAddedToRecvQueue,
	}
}

ConnectionKeySet :: struct {
	pub_key: [ECC_PUB_KEY_SIZE]u8,
	prv_key: [ECC_PRV_KEY_SIZE]u8,
	shared_key: [ECC_PUB_KEY_SIZE]u8,
}

Connection :: struct {
	id, protocol_id: u32,
	last_recv_packet_time, last_flush_time, last_read_packets_time: TimeT,
	time: TimeT,
	downloaded_bytes: uint,
	is_accepted, is_stale, is_closed: u8, // default=1
	endpoint: ^Endpoint,
	channels: [MAX_CHANNELS]^Channel,
	stats: ConnectionStats,
	driver_data, user_data: rawptr,
	connection_data: [CONNECTION_DATA_MAX_SIZE]u8,
	accept_data: [ACCEPT_DATA_MAX_SIZE]u8,
	accept_data_w_stream: WriteStream,
	accept_data_r_stream: ReadStream,

	next_packet_seq_number: u16,
	last_received_packet_seq_number: u16,
	packet_send_seq_buffer: [MAX_PACKET_ENTRIES]u32,
	packet_send_buffer: [MAX_PACKET_ENTRIES]PacketEntry,
	packet_recv_seq_buffer: [MAX_PACKET_ENTRIES]u32,

	keys1, keys2, keys3: ConnectionKeySet,
	aes_iv: [AES_BLOCKLEN]u8,

	can_decrypt, can_encrypt: u8, // default=1
}

// region EventQueue
EventType :: enum int {
	No = 0,
	Skip,
}

EVENT_QUEUE_CAPACITY :: 1_024

Event :: struct {
	type: EventType,
	data: struct #raw_union { message_info: MessageInfo, connetion: ^Connection, },
}

EventQueue :: struct {
	events: [EVENT_QUEUE_CAPACITY]Event,
	head, tail, count: uint,
}

// region PacketSimulator
NBN_USE_PACKET_SIMULATOR :: #config(NBN_USE_PACKET_SIMULATOR, -1)

when DEBUG == YES && NBN_USE_PACKET_SIMULATOR > -1 {
	// TODO
	// ...
}

// region Endpoint
ENDPOINT_OUTGOING_MESSAGE_BUFFER_SIZE :: 1_024

is_reserved_message :: #force_inline proc(type: $T) -> (bool)
{
	return (
		type == MESSAGE_CHUNK_TYPE ||
		type == CLIENT_CLOSED_MESSAGE_TYPE ||
		type == CLIENT_ACCEPTED_MESSAGE_TYPE ||
		type == BYTE_ARRAY_MESSAGE_TYPE ||
		type == PUBLIC_CRYPTO_INFO_MESSAGE_TYPE ||
		type == START_ENCRYPT_MESSAGE_TYPE ||
		type == DISCONNECTION_MESSAGE_TYPE ||
		type == CONNECTION_REQUEST_MESSAGE_TYPE
	)
}

Endpoint :: struct {
	config: Config,
	channels: [MAX_CHANNELS]ChannelType,
	message_builders: [MAX_MESSAGE_TYPES]MessageBuilder,
	message_destructors: [MAX_MESSAGE_TYPES]MessageDestructor,
	message_serializers: [MAX_MESSAGE_TYPES]MessageSerializer,
	outgoing_message_buffer: [ENDPOINT_OUTGOING_MESSAGE_BUFFER_SIZE]OutgoingMessage,
	event_queue: EventQueue,
	is_server: bool,
	next_ougoing_message: uint,
}

// region GameClient
ConnectionStatus :: enum int {
	Connected = 2,
	Disconnected,
	MsgReceived,
}

GameClient :: struct {
	endpoint: Endpoint,
	server_connection: ^Connection,
	is_connected: bool,
	ctx: rawptr,
}

@private gclient: GameClient

// region Utils
MIN :: linalg.min
MAX :: linalg.max
ABS :: linalg.abs

// Some test/debug stuff
@private YES :: "YES"
@private NO :: "NO"
@private DEBUG :: #config(DEBUG, NO)

when DEBUG == YES {
	main :: proc()
	{
		
	}
}