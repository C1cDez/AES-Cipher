#pragma once

enum
{
	ARG_INPUT,
	ARG_TEXT,
	ARG_OUTPUT,
	ARG_ENCRYPT,
	ARG_DECRYPT,
	ARG_KEY,
	ARG_PASSPHRASE,
	ARG_HASH,
	ARG_SIZE,
	ARG_MODE,
	ARG_INITVEC,
	ARG_NONCE,
	ARG_NONCELEN,
	ARG_PADDING,
	ARG_SECRET
};

typedef struct arg_param
{
	// identity
	const char* const longname;
	const char symname;
	const char requires_option;
	// parsable
	char presented;
	const char* option;
} arg_param_t;
