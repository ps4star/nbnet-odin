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
reallocator :: #force_inline proc(ptr: rawptr, size: int, old_size := 1) -> (rawptr)
{
	return mem.resize(ptr, old_size, size)
}
deallocator :: mem.free

// region Declarations
abort :: #force_inline proc(loc := #caller_location)
{
	fmt.println("abort() call; location info: ", loc)
	panic(fmt.aprintf("Now exiting..."))
}

ERROR :: -1

NBN_DEBUG :: cast(int) #config(NBN_DEBUG, -1)
NBN_DISABLE_MEMORY_POOLING :: cast(int) #config(NBN_DISABLE_MEMORY_POOLING, -1)

// region ConnectionVector
// NOTE: this type has been replaced with [dynamic]Connection
// uses of this type later in the code have been changed appropriately

// region Memory management
when NBN_DEBUG > -1 && NBN_USE_PACKET_SIMULATOR > -1 {
	MemType :: enum {
		MESSAGE_CHUNK,
		BYTE_ARRAY_MESSAGE,
		CONNECTION,
		PACKET_SIMULATOR_ENTRY,
	}
} else {
	MemType :: enum {
		MESSAGE_CHUNK,
		BYTE_ARRAY_MESSAGE,
		CONNECTION,
	}
}

MemPoolFreeBlock :: struct {
	next: ^MemPoolFreeBlock,
}

MemPool :: struct {
	blocks: [^][^]u8,
	block_size: uint,
	block_count: uint,
	block_idx: uint,
	free: ^MemPoolFreeBlock,
}

when NBN_DISABLE_MEMORY_POOLING > -1 {
	MemoryManager :: struct {
		mem_sizes: [MemType]uint,
	}
} else {
	MemoryManager :: struct {
		mem_pools: [MemType]MemPool,
	}
}

@private mem_mgr: MemoryManager

@private MemoryManager_init :: proc()
{
	when NBN_DISABLE_MEMORY_POOLING > -1 {
		log(.Debug, "MemoryManager_init without pooling!")

		mem_mgr.mem_sizes[.MESSAGE_CHUNK] = size_of(MessageChunk)
		mem_mgr.mem_sizes[.BYTE_ARRAY_MESSAGE] = size_of(ByteArrayMessage)
		mem_mgr.mem_sizes[.CONNECTION] = size_of(Connection)

		when NBN_DEBUG > -1 && NBN_USE_PACKET_SIMULATOR > -1 {
			mem_mgr.mem_sizes[.PACKET_SIMULATOR_ENTRY] = size_of(PacketSimulatorEntry)
		}
	} else {
		log(.Debug, "MemoryManager_init with pooling!")

		// NOTE(ps4star): Shouldn't these ints be constants or smth?
		MemPool_init(&mem_mgr.mem_pools[.MESSAGE_CHUNK], size_of(MessageChunk), 256)
		MemPool_init(&mem_mgr.mem_pools[.BYTE_ARRAY_MESSAGE], size_of(ByteArrayMessage), 256)
		MemPool_init(&mem_mgr.mem_pools[.CONNECTION], size_of(Connection), 16)

		when NBN_DEBUG > -1 && NBN_USE_PACKET_SIMULATOR > -1 {
			MemPool_init(&mem_mgr.mem_pools[.PACKET_SIMULATOR_ENTRY], size_of(PacketSimulatorEntry), 32)
		}
	}
}

@private MemoryManager_deinit :: proc()
{
	when !(NBN_DISABLE_MEMORY_POOLING > -1) {
		MemPool_deinit(&mem_mgr.mem_pools[.MESSAGE_CHUNK])
		MemPool_deinit(&mem_mgr.mem_pools[.BYTE_ARRAY_MESSAGE])
		MemPool_deinit(&mem_mgr.mem_pools[.CONNECTION])

		when NBN_DEBUG > -1 && NBN_USE_PACKET_SIMULATOR > -1 {
			MemPool_deinit(&mem_mgr.mem_pools[.PACKET_SIMULATOR_ENTRY])
		}
	}
}

@private MemoryManager_alloc :: proc(mem_type: MemType) -> (rawptr)
{
	when NBN_DISABLE_MEMORY_POOLING > -1 {
		return allocator(mem_mgr.mem_sizes[mem_type])
	} else {
		return MemPool_alloc(&mem_mgr.mem_pools[mem_type])
	}
}

@private MemoryManager_dealloc :: proc(ptr: rawptr, mem_type: MemType)
{
	when NBN_DISABLE_MEMORY_POOLING > -1 {
		deallocator(ptr)
	} else {
		MemPool_dealloc(&mem_mgr.mem_pools[mem_type], ptr)
	}
}

when !(NBN_DISABLE_MEMORY_POOLING > -1) {

@private MemPool_init :: proc(pool: ^MemPool, block_size: uint, initial_block_count: uint)
{
	pool.block_size = MAX(block_size, size_of(MemPoolFreeBlock))
	pool.block_idx = 0
	pool.block_count = 0
	pool.free = nil
	pool.blocks = nil

	MemPool_grow(pool, initial_block_count)
}

/*static void MemPool_Deinit(NBN_MemPool *pool)
{
    for (unsigned int i = 0; i < pool->block_count; i++)
        NBN_Deallocator(pool->blocks[i]);

    NBN_Deallocator(pool->blocks);
}*/
MemPool_deinit :: proc(pool: ^MemPool)
{
	for i: uint = 0; i < uint(pool.block_count); i += 1 {
		deallocator(pool.blocks[i])
	}

	deallocator(pool.blocks)
}

/*static void *MemPool_Alloc(NBN_MemPool *pool)
{
    if (pool->free)
    {
        void *block = pool->free;

        pool->free = pool->free->next;

        return block;
    }

    if (pool->block_idx == pool->block_count)
        MemPool_Grow(pool, pool->block_count * 2);

    void *block = pool->blocks[pool->block_idx];

    pool->block_idx++;

    return block;
}*/
MemPool_alloc :: proc(pool: ^MemPool) -> (rawptr)
{
	if pool.free != nil {
		block: rawptr = pool.free
		pool.free = pool.free.next
		return block
	}

	if pool.block_idx == pool.block_count {
		MemPool_grow(pool, pool.block_count * 2)
	}

	block: rawptr = pool.blocks[pool.block_idx]
	pool.block_idx += 1
	return block
}

/*static void MemPool_Dealloc(NBN_MemPool *pool, void *ptr)
{
    NBN_MemPoolFreeBlock *free = pool->free;

    pool->free = (NBN_MemPoolFreeBlock*)ptr;
    pool->free->next = free;
}*/
MemPool_dealloc :: proc(pool: ^MemPool, ptr: rawptr)
{
	fr: ^MemPoolFreeBlock = pool.free

	pool.free = transmute(^MemPoolFreeBlock) ptr
	pool.free.next = fr
}

/*static void MemPool_Grow(NBN_MemPool *pool, unsigned int block_count)
{
    pool->blocks = (uint8_t**)NBN_Reallocator(pool->blocks, sizeof(uint8_t *) * block_count);

    for (unsigned int i = 0; i < block_count - pool->block_count; i++)
        pool->blocks[pool->block_idx + i] = (uint8_t*)NBN_Allocator(pool->block_size);

    pool->block_count = block_count;
}*/
MemPool_grow :: proc(pool: ^MemPool, block_count: uint)
{
	pool.blocks = transmute(type_of(pool.blocks)) reallocator(pool.blocks, int(size_of([^]u8) * block_count))

	for i: uint = 0; i < block_count - pool.block_count; i += 1 {
		pool.blocks[pool.block_idx + i] = transmute([^]u8) allocator(int(pool.block_size))
	}

	pool.block_count = block_count
}

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
	where size_of(T1) == size_of([^]u8)
{
	stream->serialize_bytes_func(transmute([^]u8) v, uint(length))
}

serialize_padding :: #force_inline proc(stream: ^Stream)
{
	stream->serialize_padding_func()
}

get_required_number_of_bits_for :: proc(v: uint) -> (uint)
{
	a: uint = v | (v >> 1)
    b: uint = a | (a >> 2)
    c: uint = b | (b >> 4)
    d: uint = c | (c >> 8)
    e: uint = d | (d >> 16)
    f: uint = e >> 1

    i: uint = f - ((f >> 1) & 0x55555555)
    j: uint = (((i >> 2) & 0x33333333) + (i & 0x33333333))
    k: uint = (((j >> 4) + j) & 0x0f0f0f0f)
    l: uint = k + (k >> 8)
    m: uint = l + (l >> 16)

    return (m & 0x0000003f) + 1
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
// <see crypto.odin>














// region Packet
// <see packet.odin>

// region MessageChunk
MESSAGE_CHUNK_SIZE :: (PACKET_MAX_USER_DATA_SIZE - size_of(MessageHeader) - 2)
MESSAGE_CHUNK_TYPE :: (MAX_MESSAGE_TYPES - 1)

MessageChunk :: struct {
	id: u8,
	total: u8,
	data: [MESSAGE_CHUNK_SIZE]u8,
	outgoing_msg: ^OutgoingMessage,
}

MessageChunk_create :: proc() -> (^MessageChunk)
{
	chunk := transmute(^MessageChunk) MemoryManager_alloc(.MESSAGE_CHUNK)

	chunk.outgoing_msg = nil

	return chunk
}

MessageChunk_destroy :: proc(chunk: ^MessageChunk)
{
	MemoryManager_dealloc(chunk, .MESSAGE_CHUNK)
}

MessageChunk_serialize :: proc(msg: ^MessageChunk, stream: ^Stream) -> (int)
{
	serialize_bytes(stream, &msg.id, 1)
	serialize_bytes(stream, &msg.total, 1)
	serialize_bytes(stream, DEMOTE(&msg.data), MESSAGE_CHUNK_SIZE)

	return 0
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

when NBN_DEBUG > -1 {
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

when NBN_DEBUG > -1 && NBN_USE_PACKET_SIMULATOR > -1 {
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
// <in game_client.odin>

// region GameServer
// <in game_server.odin>

// region Utils
MIN :: linalg.min
MAX :: linalg.max
ABS :: linalg.abs

// Some test/debug stuff
when NBN_DEBUG > -1 {
	main :: proc()
	{
		
	}
}