/*
* Author: Fabian Kammel
*   Date: 27.05.2014
*
* Implements AES Encrpytion utilizing T-Tables.
* The T-Tables are set-up in the function setUpTTables();
* The round keys are derived in the function deriveKey();
* aesEncrypt() uses the normal S-Boxes and can be used to
* compute a result for comparison.
*
* IMPORTANT: deriveKey() and setUpTTables should not be called directly
this is already done in the aesEncrypt and aesEncryptWithT
functions!
*/

#include "aes.h"

uint32_t T0[256] = {0};
uint32_t T1[256] = {0};
uint32_t T2[256] = {0};
uint32_t T3[256] = {0};
uint32_t setup_done = 0;

void aes_init(aes_context *ctx, uint8_t *key, uint32_t bitness) {
	// Loop counter
	uint32_t i;
	
	// Set up the T Tables if they are still empty
	if (!setup_done) {
		setUpTTables();
	}

	// Set the array
	ctx->bitness = bitness;
	ctx->key = key;

	// If the bitness is not set, fall back to the standard value of 256
	if (ctx->bitness == 0) {
		ctx->bitness = 256;
	}
	// If the bitness value is not valid
	if (!(ctx->bitness == 128 || ctx->bitness == 192 || ctx->bitness == 256)) {
		printf("Only the values 128, 192, 256 for the bitness are valid!\n");
		return;
	}
	if (ctx->key == NULL) {
		printf("No key specified!\n");
		return;
	}
	// Set the number of rounds according to the bitness
	if (ctx->bitness == 128) {
		ctx->rounds = 10;
	}
	else if (ctx->bitness == 192) {
		ctx->rounds = 12;
	}
	else {
		ctx->rounds = 14;
	}
	// Init space for the buffers
	ctx->state = calloc(16, sizeof(uint8_t));		// Zero Init the state so we dont have to do that later
	ctx->enc_key = malloc(sizeof(uint8_t*) * (ctx->rounds + 1));
	ctx->dec_key = malloc(sizeof(uint8_t*) * (ctx->rounds + 1));
	for (i = 0; i < (ctx->rounds + 1); i++) {
		ctx->enc_key[i] = malloc(sizeof(uint8_t) * 16);
		ctx->dec_key[i] = malloc(sizeof(uint8_t) * 16);
	}

	// Calcualte the encryption key
	deriveEncryptionKey(ctx);

	// TOOD: Implement
	// Calculate the decryption key
	// deriveDecryptionKey(ctx);
}

void aes_free(aes_context * ctx) {
	// Loop counter
	uint32_t i;
	
	free(ctx->state);
	for (i = 0; i < (ctx->rounds + 1); i++) {
		free(ctx->enc_key[i]);
		free(ctx->dec_key[i]);
	}
	free(ctx->enc_key);
	free(ctx->dec_key);
}

/* T Tables are the fusion of the MixColums and the SubBytes step. */
void setUpTTables() {
	int i;
	for (i = 0; i < 256; i++) {
		T0[i] = mc2(SBox[i]) << 24 |     SBox[i]  << 16 |     SBox[i]  << 8 | mc3(SBox[i]);
		T1[i] = mc3(SBox[i]) << 24 | mc2(SBox[i]) << 16 |     SBox[i]  << 8 |     SBox[i];
		T2[i] =     SBox[i]  << 24 | mc3(SBox[i]) << 16 | mc2(SBox[i]) << 8 |     SBox[i];
		T3[i] =     SBox[i]  << 24 |     SBox[i]  << 16 | mc3(SBox[i]) << 8 | mc2(SBox[i]);
	}
	setup_done = 1;
}

void makeTRound(uint8_t state[16], uint8_t key[16]) {
	uint32_t buffer0 = T0[state[0]] ^ T1[state[5]] ^ T2[state[10]] ^ T3[state[15]] ^ ((key[0] << 24) | (key[1] << 16) | (key[2] << 8) | (key[3]));
	uint32_t buffer1 = T0[state[4]] ^ T1[state[9]] ^ T2[state[14]] ^ T3[state[3]] ^ ((key[4] << 24) | (key[5] << 16) | (key[6] << 8) | (key[7]));
	uint32_t buffer2 = T0[state[8]] ^ T1[state[13]] ^ T2[state[2]] ^ T3[state[7]] ^ ((key[8] << 24) | (key[9] << 16) | (key[10] << 8) | (key[11]));
	uint32_t buffer3 = T0[state[12]] ^ T1[state[1]] ^ T2[state[6]] ^ T3[state[11]] ^ ((key[12] << 24) | (key[13] << 16) | (key[14] << 8) | (key[15]));

	state[0] = (buffer0 >> 24) & 0xFF;
	state[1] = (buffer0 >> 16) & 0xFF;
	state[2] = (buffer0 >> 8) & 0xFF;
	state[3] = (buffer0 >> 0) & 0xFF;

	state[4] = (buffer1 >> 24) & 0xFF;
	state[5] = (buffer1 >> 16) & 0xFF;
	state[6] = (buffer1 >> 8) & 0xFF;
	state[7] = (buffer1 >> 0) & 0xFF;

	state[8] = (buffer2 >> 24) & 0xFF;
	state[9] = (buffer2 >> 16) & 0xFF;
	state[10] = (buffer2 >> 8) & 0xFF;
	state[11] = (buffer2 >> 0) & 0xFF;

	state[12] = (buffer3 >> 24) & 0xFF;
	state[13] = (buffer3 >> 16) & 0xFF;
	state[14] = (buffer3 >> 8) & 0xFF;
	state[15] = (buffer3 >> 0) & 0xFF;

	//printf("%04X, %04X, %04X, %04X\n", buffer0, buffer1, buffer2, buffer3);
}

void deriveEncryptionKey(aes_context* ctx) {
	uint32_t i, j;

	/* Copy over the first key, since it is equal to the initial key */
	for (i = 0; i < 16; i++) {
		ctx->enc_key[0][i] = ctx->key[i];
	}

	for (i = 0; i < ctx->rounds; i++) {
		/* MULTIPLE OF FOUR */
		ctx->enc_key[i + 1][0] = ctx->enc_key[i][0] ^ SBox[ctx->enc_key[i][0xD]] ^ KeyRC[i];
		ctx->enc_key[i + 1][1] = ctx->enc_key[i][1] ^ SBox[ctx->enc_key[i][0xE]];
		ctx->enc_key[i + 1][2] = ctx->enc_key[i][2] ^ SBox[ctx->enc_key[i][0xF]];
		ctx->enc_key[i + 1][3] = ctx->enc_key[i][3] ^ SBox[ctx->enc_key[i][0xC]];

		/* NOT MULTIPLE OF FOUR */
		for (j = 4; j < 16; j++) {
			ctx->enc_key[i + 1][j] = ctx->enc_key[i][j] ^ ctx->enc_key[i + 1][j - 4];
		}
	}
}

void subBytes(uint8_t state[16]) {
	int i = 0;
	for (; i < 16; i++) {
		state[i] = SBox[state[i]];
	}
}

void shiftRows(uint8_t state[16]) {
	//ROTATE LEFT BY ONE
	uint8_t buffer = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = buffer;

	//ROTATE LEFT BY TWO
	buffer = state[2];
	state[2] = state[10];
	state[10] = buffer;
	buffer = state[6];
	state[6] = state[14];
	state[14] = buffer;

	//ROTATE LEFT BY THREE
	buffer = state[3];
	state[3] = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = buffer;
}

void mixColumns(uint8_t state[16]) {
	int i = 0;
	uint8_t buffer0, buffer1, buffer2, buffer3;

	for (; i < 16; i += 4) {
		buffer0 = mc2(state[i + 0]) ^ mc3(state[i + 1]) ^ state[i + 2] ^ state[i + 3];
		buffer1 = state[i + 0] ^ mc2(state[i + 1]) ^ mc3(state[i + 2]) ^ state[i + 3];
		buffer2 = state[i + 0] ^ state[i + 1] ^ mc2(state[i + 2]) ^ mc3(state[i + 3]);
		buffer3 = mc3(state[i + 0]) ^ state[i + 1] ^ state[i + 2] ^ mc2(state[i + 3]);
		state[i + 0] = buffer0;
		state[i + 1] = buffer1;
		state[i + 2] = buffer2;
		state[i + 3] = buffer3;
	}
}

void addRoundKey(uint8_t state[16], uint8_t key[16]) {
	int i = 0;
	for (; i < 16; i++) {
		state[i] ^= key[i];
	}
}

uint8_t mc3(uint8_t byte) {
	return mc2(byte) ^ byte;
}

uint8_t mc2(uint8_t byte) {
	uint8_t flag = (byte >> 7) & 0x1;
	byte = byte << 1;
	if (flag) {
		byte ^= 0x1B;
	}
	return byte;
}

// TODO: Take length into account and make this into ecb mode!
void aes_encrypt(aes_context * ctx, uint8_t * message, uint32_t length) {
	//1. Move the message into the state
	int i;
	for (i = 0; i < 16; i++) {
		ctx->state[i] = message[i];
	}

	//2. Initial Round Key
	addRoundKey(ctx->state, ctx->enc_key[0]);

	printf("Round: %d\n", 0);
	printState(ctx->state);

	//3. Rounds 1...9
	uint32_t round = 1;
	for (; round < ctx->rounds; round++) {
		subBytes(ctx->state);
		shiftRows(ctx->state);
		mixColumns(ctx->state);
		addRoundKey(ctx->state, ctx->enc_key[round]);

		printf("Round: %d\n", round);
		printState(ctx->state);
	}

	//4. Round 10
	subBytes(ctx->state);
	shiftRows(ctx->state);
	addRoundKey(ctx->state, ctx->enc_key[ctx->rounds]);

	printf("Round: %d\n", ctx->rounds);
	printState(ctx->state);
}

void aes_encrypt_withT(aes_context * ctx, uint8_t * message, uint32_t length) {
	//1. Move the message into the state
	int i;
	for (i = 0; i < 16; i++) {
		ctx->state[i] = message[i];
	}

	//2. Initial Round Key
	addRoundKey(ctx->state, ctx->enc_key[0]);

	printf("Round: %d\n", 0);
	printState(ctx->state);

	//3. Rounds 1...9
	int round;
	for (round = 1; round < ctx->rounds; round++) {
		makeTRound(ctx->state, ctx->enc_key[round]);

		printf("Round: %d\n", round);
		printState(ctx->state);
	}

	//4. Round 10
	subBytes(ctx->state);
	shiftRows(ctx->state);
	addRoundKey(ctx->state, ctx->enc_key[ctx->rounds]);

	printf("Round: %d\n", ctx->rounds);
	printState(ctx->state);
}


void printState(uint8_t state[16]) {
	printf("%02X ", state[0]);
	printf("%02X ", state[4]);
	printf("%02X ", state[8]);
	printf("%02X ", state[12]);

	printf("\n");

	printf("%02X ", state[1]);
	printf("%02X ", state[5]);
	printf("%02X ", state[9]);
	printf("%02X ", state[13]);

	printf("\n");

	printf("%02X ", state[2]);
	printf("%02X ", state[6]);
	printf("%02X ", state[10]);
	printf("%02X ", state[14]);

	printf("\n");

	printf("%02X ", state[3]);
	printf("%02X ", state[7]);
	printf("%02X ", state[11]);
	printf("%02X ", state[15]);

	printf("\n\n");
}
