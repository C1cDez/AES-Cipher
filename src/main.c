#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "args.h"
#include "aes.h"


static int print_help(const char* progname)
{
	printf(
		"%s is a CLI utility to encrypt and decrypt files using AES-128, AES-192, and AES-256\n"
		"\t-h, --help\t\tPrints this manual\n"
		"\t-i, --input\t\tSpecify input file to process\n"
		"\t-t, --text\t\tProcess given text (in next argument) instead of file\n"
		"\t-o, --output\t\tSpecify output file\n"
		"\t-e, --encrypt\t\tEncrypt\n"
		"\t-d, --decrypt\t\tDecrypt\n"
		"\t-k, --key\t\tSet key, in hex (if length is not 32, 48, or 64 symbols, requires -s)\n"
		"\t-p, --passphrase\tNon-hex (textual) representation of the key (requires -s)\n"
		"\t-H, --hash\t\tUse SHA-256 hash of passphrase instead of it directly\n"
		"\t-s, --size\t\tSpecify key size manually: [128, 192, 256]\n"
		"\t-m, --mode\t\tSpecify block cipher mode of operation:\n"
		"\t\tecb\t\t\tElectronic Codebook (does not require -I)\n"
		"\t\tcbc\t\t\tCipher Block Chaining\n"
		"\t\tpcbc\t\t\tPropagating cipher block chaining\n"
		"\t\tcfb\t\t\tCipher Feedback\n"
		"\t\tofb\t\t\tOutput Feedback\n"
		"\t\tctr\t\t\tCounter Mode\n"
		"\t-I, --initvec\t\tSet initial vector (mandatory for all modes except ECB), in hex\n"
		"\t\t\t\t\t(in CTR should be considered a nonce)\n"
		"\t-n, --nonce\t\tSpecify nonce length for CTR mode (in bytes)\n"
		"\t\t\t\t\t(the rest of IV will be considred a counter)\n"
		"\t-c, --counter\t\tSpecify counter for CTR mode\n"
		"\t-P, --pad\t\tSpecify padding:\n"
		"\t\tzeros (0)\t\tZeros\n"
		"\t\tpkcs7 (7)\t\tPKCS-7\n"
		"\t\tansi-x923 (923)\t\tANSI X.923\n"
		"\t\tiso-9797-1 (9797)\tISO/IEC 9797-1\n"
		"\t-S, --secret\t\tDo not log sensetive information\n"
		,
		progname
	);
	return 0;
}

static void fillin_args(int argc, const char** argv, arg_param_t* params, int params_count)
{
	for (int i = 0; i < argc; i++)
	{
		const char* arg = argv[i];
		int len = (int)strlen(arg);
		if (arg[0] != '-' || len < 2) continue;

		char spec = arg[1];
		arg_param_t* ap = NULL;

		if (spec != '-')
		{
			for (int j = 0; j < params_count; j++)
			{
				if (params[j].symname == spec) { ap = params + j; break; }
			}
		}
		else
		{
			for (int j = 0; j < params_count; j++)
			{
				if (!strcmp(params[j].longname, arg + 2)) { ap = params + j; break; }
			}
		}
		
		if (ap)
		{
			ap->presented = 1;
			if (ap->requires_option)
			{
				if (spec != '-' && len > 2) ap->option = arg + 2;
				else if (i + 1 < argc) { ap->option = argv[i + 1]; i++; }
				else { ap->option = NULL; ap->presented = 0; }
			}
		}
	}
}

#define THROW(cond, ...) if (cond) { fprintf(stderr, __VA_ARGS__); return 1; }

#define XOR_ARG_THROW(arg1, arg2, arg1_thing, arg2_thing) \
	THROW(!arg1.presented && !arg2.presented, "Neither " arg1_thing " nor " arg2_thing " is specified\n"); \
	THROW(arg1.presented && arg2.presented, "Both " arg1_thing " and " arg2_thing " are specified\n"); \

static int validate_args(arg_param_t* args)
{
	char i = args[ARG_INPUT].presented, o = args[ARG_OUTPUT].presented, t = args[ARG_TEXT].presented;
	THROW(!((i && o && !t) || (!i && !o && t)),
		"Invalid data configuration. Input file requires an output file. Text doesn't require output file\n");
	XOR_ARG_THROW(args[ARG_ENCRYPT], args[ARG_DECRYPT], "encrypt", "decrypt");
	XOR_ARG_THROW(args[ARG_KEY], args[ARG_PASSPHRASE], "key", "passphrase");
	THROW(args[ARG_PASSPHRASE].presented && !args[ARG_SIZE].presented, "Size must be specified with passprase\n");
	return 0;
}

int process(const arg_param_t* args);

// void __test__();

int main(int argc, char** argv)
{
	if (argc == 1 || !strcmp("--help", argv[1]) || !strcmp("-h", argv[1])) return print_help(argv[0]);

	arg_param_t args[15] = {
		[ARG_INPUT] =		{ "input",		'i', 1 },
		[ARG_TEXT] =		{ "text",		't', 1 },
		[ARG_OUTPUT] =		{ "output",		'o', 1 },
		[ARG_ENCRYPT] =		{ "encrypt",	'e', 0 },
		[ARG_DECRYPT] =		{ "decrypt",	'd', 0 },
		[ARG_KEY] =			{ "key",		'k', 1 },
		[ARG_PASSPHRASE] =	{ "passphrase",	'p', 1 },
		[ARG_HASH] =		{ "hash",		'H', 0 },
		[ARG_SIZE] =		{ "size",		's', 1 },
		[ARG_MODE] =		{ "mode",		'm', 1 },
		[ARG_INITVEC] =		{ "initvec",	'I', 1 },
		[ARG_NONCE] =		{ "nonce",		'n', 1 },
		[ARG_COUNTER] =		{ "counter",	'c', 1 },
		[ARG_PADDING] =		{ "pad",		'P', 1 },
		[ARG_SECRET] =		{ "secret",		'S', 0 },
	};

	fillin_args(argc - 1, argv + 1, args, __crt_countof(args));

	if (validate_args(args)) return 1;
	
	return process(args);
}
