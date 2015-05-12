#include <stdio.h>
#include <stdint.h>

#include "aes.h"

uint8_t TestValues[16] = { 112, 160, 201, 73, 3, 157, 206, 218, 177, 197, 122, 66, 110, 70, 251, 86 };

uint8_t msg[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

int compareBuf(uint8_t buf[16], uint8_t Testbuf[16])
{
	int i;
	for (i = 0; i < 16; i++)
	{
		if (buf[i] != Testbuf[i])
		{
			return 1;
		}
	}
	return 0;
}

int main(int argc, char** argv) {
	aes_context ctx;
	aes_init(&ctx, key, 128);


	printState(ctx.enc_key[0]);
	printState(ctx.enc_key[1]);
	printState(ctx.enc_key[2]);
	printState(ctx.enc_key[3]);

	aes_encrypt(&ctx, msg, 16);

	printState(ctx.state);
}