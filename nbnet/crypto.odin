package nbnet
import "core:fmt"
import "core:math"
import "core:math/linalg"
import "core:mem"
import "core:os"
import "core:time"
import "core:strings"
import "core:slice"

// Use chacha20 for CSPRNG type
import chacha20 "core:crypto/chacha20"

// Use poly1305 for poly1305 functionality
import poly1305 "core:crypto/poly1305"

// region Encryption
/// sub region ECDH
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

/// sub region AES
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

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
Nb :: 4

when AES256 > -1 && AES256 == 1 {
	Nk :: 8
	Nr :: 14
} else when AES192 > -1 && AES192 == 1 {
	Nk :: 6
	Nr :: 12
} else {
	Nk :: 4        // The number of 32 bit words in a key.
	Nr :: 10       // The number of rounds in AES Cipher.
}

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
NBN_MULTIPLY_AS_A_FUNCTION :: #config(NBN_MULTIPLY_AS_A_FUNCTION, -1)

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
@private StateT :: [4][4]u8

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
@private sbox: [256]u8 = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }

@private rsbox: [256]u8 = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
@private Rcon: [11]u8 = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
get_sbox_value :: #force_inline proc(num: $T) -> (u8) { return sbox[num] }
get_sbox_invert :: #force_inline proc(num: $T) -> (u8) { return rsbox[num] }

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
@private key_expansion :: proc(round_key: [^]u8, key: [^]u8)
{
	i, j, k: uint
    tempa: [4]u8 // Used for the column/row operations

    // The first round key is the key itself.
    for i = 0; i < Nk; i += 1 {
        round_key[(i * 4) + 0] = key[(i * 4) + 0];
        round_key[(i * 4) + 1] = key[(i * 4) + 1];
        round_key[(i * 4) + 2] = key[(i * 4) + 2];
        round_key[(i * 4) + 3] = key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for i = Nk; i < Nb * (Nr + 1); i += 1 {
        {
            k = (i - 1) * 4;
            tempa[0]=round_key[k + 0];
            tempa[1]=round_key[k + 1];
            tempa[2]=round_key[k + 2];
            tempa[3]=round_key[k + 3];

        }

        if i % Nk == 0 {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            {
                u8tmp := tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = u8tmp;
            }

            // SubWord() is a function that takes a four-byte input word and 
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
            {
                tempa[0] = get_sbox_value(tempa[0]);
                tempa[1] = get_sbox_value(tempa[1]);
                tempa[2] = get_sbox_value(tempa[2]);
                tempa[3] = get_sbox_value(tempa[3]);
            }

            tempa[0] = tempa[0] ~ Rcon[i/Nk];
        }
when AES256 > -1 && AES256 == 1 {
        if i % Nk == 4 {
            // Function Subword()
            {
                tempa[0] = get_sbox_value(tempa[0]);
                tempa[1] = get_sbox_value(tempa[1]);
                tempa[2] = get_sbox_value(tempa[2]);
                tempa[3] = get_sbox_value(tempa[3]);
            }
        }
}
        j = i * 4; k=(i - Nk) * 4;
        round_key[j + 0] = round_key[k + 0] ~ tempa[0];
        round_key[j + 1] = round_key[k + 1] ~ tempa[1];
        round_key[j + 2] = round_key[k + 2] ~ tempa[2];
        round_key[j + 3] = round_key[k + 3] ~ tempa[3];
    }
}

@private AES_init_ctx_iv :: proc(ctx: ^AESCtx, key: [^]u8, iv: [^]u8)
{
	key_expansion(DEMOTE(&ctx.round_key), key)
	mem.copy(DEMOTE(&ctx.iv), iv, AES_BLOCKLEN)
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
@private add_round_key :: proc(round: u8, state: ^StateT, round_key: [^]u8)
{
	i, j: u8
	for i = 0; i < 4; i += 1 {
		for j = 0; j < 4; j += 1 {
			(state^)[i][j] ~= round_key[(round * Nb * 4) + (i * Nb) + j]
		}
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
@private sub_bytes :: proc(state: ^StateT)
{
	i, j: u8
	for i = 0; i < 4; i += 1 {
		for j = 0; j < 4; j += 1 {
			(state^)[j][i] = get_sbox_value((state^)[j][i])
		}
	}
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
@private shift_rows :: proc(state: ^StateT)
{
	temp: u8

	// Rotate first row 1 columns to left  
    temp           = (state^)[0][1];
    (state^)[0][1] = (state^)[1][1];
    (state^)[1][1] = (state^)[2][1];
    (state^)[2][1] = (state^)[3][1];
    (state^)[3][1] = temp;

    // Rotate second row 2 columns to left  
    temp           = (state^)[0][2];
    (state^)[0][2] = (state^)[2][2];
    (state^)[2][2] = temp;

    temp           = (state^)[1][2];
    (state^)[1][2] = (state^)[3][2];
    (state^)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp           = (state^)[0][3];
    (state^)[0][3] = (state^)[3][3];
    (state^)[3][3] = (state^)[2][3];
    (state^)[2][3] = (state^)[1][3];
    (state^)[1][3] = temp;
}

@private xtime :: proc(x: u8) -> (u8)
{
	return ((x<<1) ~ (((x>>7) & 1) * 0x1b))
}

// MixColumns function mixes the columns of the state matrix
@private mix_columns :: proc(state: ^StateT)
{
	i: u8
	tmp, tm, t: u8

	for i = 0; i < 4; i += 1 {
		t   = (state^)[i][0];
        tmp = (state^)[i][0] ~ (state^)[i][1] ~ (state^)[i][2] ~ (state^)[i][3] ;
        tm  = (state^)[i][0] ~ (state^)[i][1] ; tm = xtime(tm);  (state^)[i][0] ~= tm ~ tmp ;
        tm  = (state^)[i][1] ~ (state^)[i][2] ; tm = xtime(tm);  (state^)[i][1] ~= tm ~ tmp ;
        tm  = (state^)[i][2] ~ (state^)[i][3] ; tm = xtime(tm);  (state^)[i][2] ~= tm ~ tmp ;
        tm  = (state^)[i][3] ~ t ;              tm = xtime(tm);  (state^)[i][3] ~= tm ~ tmp ;
	}
}

// The only diff. here is that one is inlined and the other isn't
when NBN_MULTIPLY_AS_A_FUNCTION > 0 {
	@private Multiply :: proc(x, y: u8) -> (u8)
	{
		return (((y & 1) * x) ~
	            ((y>>1 & 1) * xtime(x)) ~
	            ((y>>2 & 1) * xtime(xtime(x))) ~
	            ((y>>3 & 1) * xtime(xtime(xtime(x)))) ~
	            ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))) /* this last call to xtime() can be omitted */
	}
} else {
	@private Multiply :: #force_inline proc(x, y: u8) -> (u8)
	{
		return (((y & 1) * x) ~
	            ((y>>1 & 1) * xtime(x)) ~
	            ((y>>2 & 1) * xtime(xtime(x))) ~
	            ((y>>3 & 1) * xtime(xtime(xtime(x)))) ~
	            ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))) /* this last call to xtime() can be omitted */
	}
}

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
/*static void InvMixColumns(state_t* state)
{
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i)
    { 
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}*/


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
/*static void InvSubBytes(state_t* state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = getSBoxInvert((*state)[j][i]);
        }
    }
}*/

/*static void InvShiftRows(state_t* state)
{
    uint8_t temp;

    // Rotate first row 1 columns to right  
    temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    // Rotate second row 2 columns to right 
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}*/

// Cipher is the main function that encrypts the PlainText.
/*static void Cipher(state_t* state, uint8_t* RoundKey)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0, state, RoundKey); 

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (round = 1; round < Nr; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(Nr, state, RoundKey);
}*/

/*static void InvCipher(state_t* state,uint8_t* RoundKey)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(Nr, state, RoundKey); 

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (round = (Nr - 1); round > 0; --round)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(round, state, RoundKey);
        InvMixColumns(state);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(0, state, RoundKey);
}*/

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/

/*static void XorWithIv(uint8_t* buf, uint8_t* Iv)
{
    uint8_t i;
    for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
    {
        buf[i] ^= Iv[i];
    }
}*/

/*static void AES_CBC_encrypt_buffer(struct AES_ctx *ctx,uint8_t* buf, uint32_t length)
{
    uintptr_t i;
    uint8_t *Iv = ctx->Iv;
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        XorWithIv(buf, Iv);
        Cipher((state_t*)buf, ctx->RoundKey);
        Iv = buf;
        buf += AES_BLOCKLEN;
        //printf("Step %d - %d", i/16, i);
    }
    /* store Iv in ctx for next call */
    memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}*/

/*static void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf,  uint32_t length)
{
    uintptr_t i;
    uint8_t storeNextIv[AES_BLOCKLEN];
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        memcpy(storeNextIv, buf, AES_BLOCKLEN);
        InvCipher((state_t*)buf, ctx->RoundKey);
        XorWithIv(buf, ctx->Iv);
        memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }
}*/

/// sub region Poly1305
POLY1305_KEYLEN :: 32
POLY1305_TAGLEN :: 16

/// sub region CSPRNG
@private _CHACHA20 :: "chacha20"
@private _POLY1305 :: "poly1305"

@(private="package") CSPRNG :: rawptr
when ODIN_OS == .Windows {
	// Odin compat
	// This is necessary because we don't have Odin headers for windows stuff
	// So we're not using wincrypt here, just a standard Odin crypto lib
	// Since we may want to customize which alg. we use though, we use a type alias to be safe
	NBNO_WIN_WHICH_CSPRNG_CRYPTO :: #config(NBNO_WIN_WHICH_CSPRNG_CRYPTO, _POLY1305)

	// TODO(ps4star): consider adding user comp flags to set specific crypto lib to use for CSPRNG
	when NBNO_WIN_WHICH_CSPRNG_CRYPTO == _POLY1305 {
		@private WinCryptoT :: poly1305.Context
		@private WIN_CSPRNG_K := make([]byte, poly1305.KEY_SIZE)
	}

	@private
	CSPRNG_TYPE :: struct #raw_union {
		object: CSPRNG,
		crypt: ^WinCryptoT,
	}

	@private WIN_CSPRNG_init :: proc(csprng: ^CSPRNG_TYPE)
	{
		// Alloc the actual crypto Context
		csprng.crypt = new(WinCryptoT)

		when NBNO_WIN_WHICH_CSPRNG_CRYPTO == _POLY1305 {
			poly1305.init(csprng.crypt, WIN_CSPRNG_K)
		}
	}

	@private WIN_CSPRNG_is_valid :: proc(crypt: ^WinCryptoT) -> (bool)
	{
		when NBNO_WIN_WHICH_CSPRNG_CRYPTO == _POLY1305 {
			return crypt._is_initialized
		}
	}

	@private WIN_CSPRNG_gen :: proc(crypt: ^WinCryptoT)
	{
		when NBNO_WIN_WHICH_CSPRNG_CRYPTO == _POLY1305 {
			
		}
	}

	@private WIN_CSPRNG_destroy :: proc(crypt: ^WinCryptoT)
	{
		free(crypt)
	}

	/*static CSPRNG csprng_create()
	{
	    CSPRNG_TYPE csprng;
	    if (!CryptAcquireContextA( &csprng.hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ))
	        csprng.hCryptProv = 0;
	    return csprng.object;
	}*/
	@(private="package")
	csprng_create :: proc() -> (CSPRNG)
	{
		csprng := CSPRNG_TYPE{}
		WIN_CSPRNG_init(&csprng)
		return csprng.object
	}

	/*static int csprng_get( CSPRNG object, void* dest, unsigned long long size )
	{
	    // Alas, we have to be pedantic here. csprng_get().size is a 64-bit entity.
	    // However, CryptGenRandom().size is only a 32-bit DWORD. So we have to make sure failure
	    // isn't from providing less random data than requested, even if absurd.
	    unsigned long long n;

	    CSPRNG_TYPE csprng;
	    csprng.object = object;
	    if (!csprng.hCryptProv) return 0;

	    n = size >> 30;
	    while (n--)
	        if (!CryptGenRandom( csprng.hCryptProv, 1UL << 30, (BYTE*)dest )) return 0;

	    return !!CryptGenRandom( csprng.hCryptProv, size & ((1ULL << 30) - 1), (BYTE*)dest );
	}*/
	@(private="package")
	csprng_get :: proc(object: CSPRNG, dest: [^]byte, size: u128) -> (bool)
	{

		csprng := CSPRNG_TYPE{}
		csprng.object = object
		if !WIN_CSPRNG_is_valid(csprng.crypt) {
			return false
		}

		WIN_CSPRNG_gen(csprng.crypt)
		return true
	}

	/*static CSPRNG csprng_destroy( CSPRNG object )
	{
	    CSPRNG_TYPE csprng;
	    csprng.object = object;
	    if (csprng.hCryptProv) CryptReleaseContext( csprng.hCryptProv, 0 );
	    return 0;
	}*/
	@(private="package")
	csprng_destroy :: proc(object: CSPRNG) -> (int)
	{
		csprng := CSPRNG_TYPE{}
		csprng.object = object
		if WIN_CSPRNG_is_valid(csprng.crypt) {
			WIN_CSPRNG_destroy(csprng.crypt)
		}

		return 0
	}
} else {
	CSPRNG_TYPE :: struct #raw_union {
		object: CSPRNG,
		urandom: FileT, // *FILE
	}

	@(private="package")
	csprng_create :: proc() -> (CSPRNG)
	{
		csprng := CSPRNG_TYPE{}
		err: os.Errno; csprng.urandom, err = os.open("/dev/urandom", os.O_RDONLY)
		assert(err > 0, fmt.aprintf("Error when trying to open /dev/urandom."))

		return csprng.object
	}

	@(private="package")
	csprng_get :: proc(object: CSPRNG, dest: [^]byte, size: u128) -> (bool)
	{
		csprng := CSPRNG_TYPE{}
		csprng.object = object

		bytes_read, err := os.read(csprng.urandom, slice.from_ptr((^byte)(dest), int(size)))
		did_read_correctly := (bytes_read == int(size))

		return did_read_correctly
	}

	@(private="package")
	csprng_destroy :: proc(object: CSPRNG) -> (int)
	{
		csprng := CSPRNG_TYPE{}
		csprng.object = object
		os.close(csprng.urandom)
		return 0
	}
}