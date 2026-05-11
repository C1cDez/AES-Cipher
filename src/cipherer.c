#include "args.h"
#include "aes.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// HELPERS

static inline int _to_hex_(char c)
{
	if ('0' <= c && c <= '9') return c - '0';
	else if ('a' <= c && c <= 'f') return c - 'a' + 10;
	else return -1;
}
static int read_hex_string(uint8_t* out, const char* str, int size)
{
	if (strlen(str) % 2)
	{
		printf("Hex string must be aligned with bytes\n");
		return 1;
	}

	int rem = (int)strlen(str);
	int i = 0;
	while (rem > 0 && i < size)
	{
		char a1 = _to_hex_(str[0]), a2 = _to_hex_(str[1]);
		if (a1 == -1 || a2 == -1) return 1;
		out[i] = (a1 << 4) | a2;
		str += 2;
		rem -= 2;
		i++;
	}

	return 0;
}

// SHA256

#define ROTR32(x, n) (((x) >> n) | ((x) << (32 - n)))
#define Maj(x, y, z) (((x) & (y)) ^ ((y) & (z)) ^ ((z) & (x)))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define s0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define s1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))
#define S0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define S1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))

static const uint32_t SHA256_K_TABLE[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_process(const uint8_t* chunk, uint32_t* hs)
{
	uint32_t a = hs[0], b = hs[1], c = hs[2], d = hs[3], e = hs[4], f = hs[5], g = hs[6], h = hs[7];
	uint32_t temp1, temp2, W[64];

	for (int i = 0; i < 16; i++)
		W[i] = ((uint32_t)chunk[i * 4] << 24) | ((uint32_t)chunk[i * 4 + 1] << 16) |
		((uint32_t)chunk[i * 4 + 2] << 8) | ((uint32_t)chunk[i * 4 + 3]);
	for (int i = 16; i < 64; i++)
		W[i] = W[i - 16] + s0(W[i - 15]) + W[i - 7] + s1(W[i - 2]);

	for (int i = 0; i < 64; i++)
	{
		temp1 = h + S1(e) + Ch(e, f, g) + SHA256_K_TABLE[i] + W[i];
		temp2 = S0(a) + Maj(a, b, c);
		h = g; g = f; f = e;
		e = d + temp1;
		d = c; c = b; b = a;
		a = temp1 + temp2;
	}

	hs[0] += a;
	hs[1] += b;
	hs[2] += c;
	hs[3] += d;
	hs[4] += e;
	hs[5] += f;
	hs[6] += g;
	hs[7] += h;
}

static void hash_keystr(uint8_t* keybuf, const char* passphrase, int size)
{
	uint32_t state[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

	uint8_t buf[64] = { 0 };
	memcpy(buf, passphrase, min(64, strlen(passphrase)));
	sha256_process(buf, state);

	uint32_t* wkeybuf = (uint32_t*)keybuf;
	for (int i = 0; i < size / 4; i++) wkeybuf[i] = state[i];
}

// KEY

static int create_key(aes_key_t* key, const arg_param_t* args)
{
	int keysize = -1;
	uint8_t keybuf[32] = { 0 };

	if (args[ARG_KEY].presented)
	{
		const char* keystr = args[ARG_KEY].option;
		switch (strlen(keystr))
		{
		case 32: keysize = 128; break;
		case 48: keysize = 192; break;
		case 64: keysize = 256; break;
		}
		if (args[ARG_SIZE].presented) keysize = atoi(args[ARG_SIZE].option);
		
		if (keysize != 128 && keysize != 192 && keysize != 256)
			{ printf("Invalid key size. Must be 128, 192, or 256\n"); return 1; }

		if (read_hex_string(keybuf, keystr, keysize >> 3)) return 3;
	}
	else if (args[ARG_PASSPHRASE].presented)
	{
		keysize = atoi(args[ARG_SIZE].option);
		if (keysize != 128 && keysize != 192 && keysize != 256)
			{ printf("Invalid key size. Must be 128, 192, or 256\n"); return 1; }

		const char* passphrase = args[ARG_PASSPHRASE].option;
		if (args[ARG_HASH].presented)
			hash_keystr(keybuf, passphrase, keysize >> 3);
		else
			memcpy(keybuf, passphrase, min(strlen(passphrase), keysize >> 3));
	}

	int keytype = -1;
	switch (keysize)
	{
	case 128: keytype = KEY128; break;
	case 192: keytype = KEY192; break;
	case 256: keytype = KEY256; break;
	default: printf("Unexpected error during key creation\n"); return 1;
	}
	aes_key_new(key, keytype, keybuf);
	return 0;
}

enum
{
	MODE_ECB,
	MODE_CBC,
	MODE_PCBC,
	MODE_CFB,
	MODE_OFB,
	MODE_CTR
};
enum
{
	PAD_ZEROS,
	PAD_PKCS7,
	PAD_ANSI_X923,
	PAD_IEC_9797_1,
};
typedef struct
{
	int mode;
	int padding;
	uint8_t temp[16];
} aes_ctx_params_t;

static void encrypt_ctx(const aes_key_t* key, aes_ctx_params_t* ctx, uint8_t plain[16], uint8_t cipher[16])
{
	if (ctx->mode == MODE_ECB)
		aes_encrypt_block(plain, key, cipher);
	else if (ctx->mode == MODE_CBC)
	{
		for (int i = 0; i < 16; i++)
			plain[i] ^= ctx->temp[i];
		aes_encrypt_block(plain, key, cipher);
		memcpy(ctx->temp, cipher, 16);
	}
	else if (ctx->mode == MODE_PCBC)
	{
		for (int i = 0; i < 16; i++)
			plain[i] ^= ctx->temp[i];
		aes_encrypt_block(plain, key, cipher);
		for (int i = 0; i < 16; i++)
			ctx->temp[i] = plain[i] ^ cipher[i];
	}
	else if (ctx->mode == MODE_CFB)
	{
		aes_encrypt_block(ctx->temp, key, cipher);
		for (int i = 0; i < 16; i++)
			cipher[i] ^= plain[i];
		memcpy(ctx->temp, cipher, 16);
	}
	else if (ctx->mode == MODE_OFB)
	{
		aes_encrypt_block(ctx->temp, key, cipher);
		memcpy(ctx->temp, cipher, 16);
		for (int i = 0; i < 16; i++)
			cipher[i] ^= plain[i];
	}
	else if (ctx->mode == MODE_CTR)
	{
		aes_encrypt_block(ctx->temp, key, cipher);
		for (int i = 0; i < 16; i++)
			cipher[i] ^= plain[i];
		(*((uint64_t*)ctx->temp))++;
	}
}
static void decrypt_ctx(const aes_key_t* key, aes_ctx_params_t* ctx, uint8_t cipher[16], uint8_t plain[16])
{
	if (ctx->mode == MODE_ECB)
		aes_decrypt_block(cipher, key, plain);
	else if (ctx->mode == MODE_CBC)
	{
		aes_decrypt_block(cipher, key, plain);
		for (int i = 0; i < 16; i++)
			plain[i] ^= ctx->temp[i];
		memcpy(ctx->temp, cipher, 16);
	}
	else if (ctx->mode == MODE_PCBC)
	{
		aes_decrypt_block(cipher, key, plain);
		for (int i = 0; i < 16; i++)
			plain[i] ^= ctx->temp[i];
		for (int i = 0; i < 16; i++)
			ctx->temp[i] = cipher[i] ^ plain[i];
	}
	else if (ctx->mode == MODE_CFB)
	{
		aes_encrypt_block(ctx->temp, key, plain);
		for (int i = 0; i < 16; i++)
			plain[i] ^= cipher[i];
		memcpy(ctx->temp, cipher, 16);
	}
	else if (ctx->mode == MODE_OFB)
	{
		aes_encrypt_block(ctx->temp, key, plain);
		memcpy(ctx->temp, plain, 16);
		for (int i = 0; i < 16; i++)
			plain[i] ^= cipher[i];
	}
	else if (ctx->mode == MODE_CTR)
	{
		aes_encrypt_block(ctx->temp, key, plain);
		for (int i = 0; i < 16; i++)
			plain[i] ^= cipher[i];
		(*((uint64_t*)ctx->temp))++;
	}
}

static void insert_padding(int pad, const uint8_t plain[16], int leftlen, uint8_t output[16])
{
	memset(output, 0, 16);
	memcpy(output, plain, leftlen);
	if (pad == PAD_PKCS7)
		memset(output + leftlen, 16 - leftlen, 16 - leftlen);
	else if (pad == PAD_ANSI_X923)
	{
		memset(output + leftlen, 0, 16 - leftlen);
		output[15] = 16 - leftlen;
	}
	else if (pad == PAD_IEC_9797_1)
	{
		output[leftlen] = 0x80;
		memset(output + leftlen + 1, 0, 15 - leftlen);
	}
}
static int extract_padding(int pad, const uint8_t padded[16], uint8_t output[16], int* leftlen)
{
	memcpy(output, padded, 16);
	if (pad == PAD_ZEROS)
	{
		for (int i = 15; i >= 0; i--)
		{
			if (padded[i]) { *leftlen = i + 1; break; }
		}
	}
	else if (pad == PAD_PKCS7 || pad == PAD_ANSI_X923)
	{
		int padsize = padded[15];
		if (padsize > 16) return 1;
		*leftlen = 16 - padsize;
	}
	else if (pad == PAD_IEC_9797_1)
	{
		int found = 0;
		for (int i = 15; i >= 0; i--)
		{
			if (padded[i] == 0x80) { *leftlen = i; found = 1; break; }
		}
		if (!found) return 1;
	}
	return 0;
}

static int process_text(const aes_key_t* key, aes_ctx_params_t* ctx, const arg_param_t* args)
{
	const char* text = args[ARG_TEXT].option;

	putchar('\n');

	uint8_t buf[16] = { 0 };
	uint8_t outbuf[16] = { 0 };
	int len = (int)strlen(text);

	if (args[ARG_ENCRYPT].presented)
	{
		while (len > 16)
		{
			memcpy(buf, text, 16);
			encrypt_ctx(key, ctx, buf, outbuf);
			for (int i = 0; i < 16; i++) printf("%02x", outbuf[i]);
			text += 16;
			len -= 16;
			memset(buf, 0, 16);
		}

		memcpy(buf, text, len);
		insert_padding(ctx->padding, buf, len, outbuf);
		encrypt_ctx(key, ctx, outbuf, buf);
		for (int i = 0; i < 16; i++) printf("%02x", buf[i]);
	}
	else if (args[ARG_DECRYPT].presented)
	{
		while (len > 32)
		{
			read_hex_string(buf, text, 16);
			decrypt_ctx(key, ctx, buf, outbuf);
			for (int i = 0; i < 16; i++) putchar(outbuf[i]);
			text += 32;
			len -= 32;
			memset(buf, 0, 16);
		}

		read_hex_string(buf, text, 16);
		decrypt_ctx(key, ctx, buf, outbuf);
		int lastlen = 0;
		if (extract_padding(ctx->padding, outbuf, buf, &lastlen))
		{
			printf("\nPADDING WAS CORRUPTED\n");
			return 1;
		}
		for (int i = 0; i < lastlen; i++) putchar(buf[i]);
	}
	
	return 0;
}

static int process_file(const aes_key_t* key, aes_ctx_params_t* ctx, const arg_param_t* args)
{
	FILE* fin = fopen(args[ARG_INPUT].option, "rb");
	if (!fin)
	{
		printf("Couldn't open '%s'\n", args[ARG_INPUT].option);
		return 1;
	}
	fseek(fin, 0, SEEK_END);
	int finsize = ftell(fin);
	rewind(fin);

	FILE* fout = fopen(args[ARG_OUTPUT].option, "wb");
	if (!fout)
	{
		printf("Couldn't open '%s'\n", args[ARG_OUTPUT].option);
		fclose(fin);
		return 1;
	}

	if (args[ARG_ENCRYPT].presented)
	{
		uint8_t buf[16] = { 0 };
		uint8_t outbuf[16] = { 0 };
		int len = 0;
		while ((len = fread(buf, 1, 16, fin)) == 16)
		{
			encrypt_ctx(key, ctx, buf, outbuf);
			fwrite(outbuf, 1, 16, fout);
			memset(buf, 0, 16);
		}

		insert_padding(ctx->padding, buf, len, outbuf);
		encrypt_ctx(key, ctx, outbuf, buf);
		fwrite(buf, 1, 16, fout);

		printf("File '%s' was successfully encrypted. Result is in '%s'\n", 
			args[ARG_INPUT].option, args[ARG_OUTPUT].option);
	}
	else if (args[ARG_DECRYPT].presented)
	{
		uint8_t buf[16] = { 0 };
		uint8_t outbuf[16] = { 0 };
		int len = 0;
		while ((len = fread(buf, 1, 16, fin)) == 16 && finsize > 16)
		{
			decrypt_ctx(key, ctx, buf, outbuf);
			fwrite(outbuf, 1, 16, fout);
			memset(buf, 0, 16);
			finsize -= 16;
		}

		decrypt_ctx(key, ctx, buf, outbuf);
		int lastlen = 0;
		if (extract_padding(ctx->padding, outbuf, buf, &lastlen))
		{
			printf("Looks like file '%s' was corrupted: unable to align with selected padding\n", 
				args[ARG_INPUT].option);
			fclose(fin); fclose(fout);
			return 1;
		}
		fwrite(buf, 1, lastlen, fout);

		printf("File '%s' was successfully decrypted. Result is in '%s'\n",
			args[ARG_INPUT].option, args[ARG_OUTPUT].option);
	}

	fclose(fin);
	fclose(fout);

	return 0;
}

static void print_aes_ctx_params(const aes_ctx_params_t* params)
{
	const char* mode = NULL, * padding = NULL;
	switch (params->mode)
	{
	case MODE_ECB: mode = "ECB"; break;
	case MODE_CBC: mode = "CBC"; break;
	case MODE_PCBC: mode = "PCBC"; break;
	case MODE_CFB: mode = "CFB"; break;
	case MODE_OFB: mode = "OFB"; break;
	case MODE_CTR: mode = "CTR"; break;
	default: mode = "[UNDEFINED]";
	}
	switch (params->padding)
	{
	case PAD_ZEROS: padding = "Zeros"; break;
	case PAD_PKCS7: padding = "PKCS-7"; break;
	case PAD_ANSI_X923: padding = "ANSI X.923"; break;
	case PAD_IEC_9797_1: padding = "ISO/IEC 9797-1"; break;
	}
	if (params->mode != MODE_ECB)
	{
		printf("Mode: %s\nPadding: %s\nIV: ", mode, padding);
		for (int i = 0; i < 16; i++)
			printf("%02x", params->temp[i]);
		putchar('\n');
	}
	else
		printf("Mode: ECB\nPadding: %s\n", padding);
}
static int generate_aes_ctx_params(aes_ctx_params_t* params, const arg_param_t* args)
{
	if (args[ARG_MODE].presented)
	{
		const char* modename = args[ARG_MODE].option;
		if (!strcmp(modename, "ecb")) params->mode = MODE_ECB;
		else if (!strcmp(modename, "cbc")) params->mode = MODE_CBC;
		else if (!strcmp(modename, "pcbc")) params->mode = MODE_PCBC;
		else if (!strcmp(modename, "cfb")) params->mode = MODE_CFB;
		else if (!strcmp(modename, "ofb")) params->mode = MODE_OFB;
		else if (!strcmp(modename, "ctr")) params->mode = MODE_CTR;
		else { printf("Undefined mode: %s\n", modename); return 1; }
	}
	else params->mode = MODE_ECB;

	if (args[ARG_PADDING].presented)
	{
		const char* padname = args[ARG_PADDING].option;
		if (!strcmp(padname, "zeros") || !strcmp(padname, "0")) params->padding = PAD_ZEROS;
		else if (!strcmp(padname, "pkcs7") || !strcmp(padname, "7")) params->padding = PAD_PKCS7;
		else if (!strcmp(padname, "ansi-x923") || !strcmp(padname, "923")) params->padding = PAD_ANSI_X923;
		else if (!strcmp(padname, "iec-9797-1") || !strcmp(padname, "9797")) params->padding = PAD_IEC_9797_1;
		else { printf("Undefined padding: %s\n", padname); return 1; }
	}
	else params->padding = PAD_ZEROS;

	if (params->mode != MODE_ECB)
	{
		if (args[ARG_INITVEC].presented)
		{
			if (read_hex_string(params->temp, args[ARG_INITVEC].option, 16)) return 1;
		}
		else
		{
			printf("In all modes except ECB, IV is required. (In CTR mode IV is considered a counter). Use -I, --initvec\n");
			return 1;
		}
	}

	if (!args[ARG_SECRET].presented) print_aes_ctx_params(params);

	return 0;
}

int process(const arg_param_t* args)
{
	aes_key_t key = { 0 };
	if (create_key(&key, args))
	{
		printf("Failed to derive the key\n");
		return 1;
	}
	aes_key_expand(&key);

	if (!args[ARG_SECRET].presented)
	{
		printf("Key was successfully derived: ");
		for (int i = 0; i < (key.type & 0x3f); i++) printf("%02x", key.content.bytes[i]);
		putchar('\n');
	}
	
	aes_ctx_params_t aes_ctx = { .mode = 0, .padding = 0, .temp = { 0 } };
	if (generate_aes_ctx_params(&aes_ctx, args))
	{
		printf("Failed to generate cipher spec\n");
		aes_key_cleanup(&key);
		return 1;
	}

	if (args[ARG_TEXT].presented)
	{
		if (process_text(&key, &aes_ctx, args))
		{
			printf("Failed to process text\n");
			aes_key_cleanup(&key);
			return 1;
		}
	}
	else
	{
		if (process_file(&key, &aes_ctx, args))
		{
			printf("Failed to process file\n");
			aes_key_cleanup(&key);
			return 1;
		}
	}

	aes_key_cleanup(&key);
	return 0;
}
