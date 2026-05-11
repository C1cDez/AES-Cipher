#pragma once

#include <stdint.h>

// KEY = (ROUNDS << 6) | (BYTES OF INITIAL KEY) & 0x3f
enum key_type
{
	KEY128 = (10 << 6) | (128 >> 3),
	KEY192 = (12 << 6) | (192 >> 3),
	KEY256 = (14 << 6) | (256 >> 3)
};

typedef struct
{
	enum key_type type;
	union
	{
		uint32_t* words;
		uint8_t* bytes;
	} content;
} aes_key_t;

void aes_key_new(aes_key_t* key, enum key_type type, uint8_t* init);
void aes_key_cleanup(aes_key_t* key);

void aes_key_expand(aes_key_t* key);

void aes_encrypt_block(const uint8_t plaintext[16], aes_key_t* key, uint8_t ciphertext[16]);
void aes_decrypt_block(const uint8_t ciphertext[16], aes_key_t* key, uint8_t plaintext[16]);
