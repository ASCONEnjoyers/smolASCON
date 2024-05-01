
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


uint64_t key[2], *key_d, nonce[2];
uint64_t state[5] = { 0 }, t[5] = { 0 };
uint64_t constants[16] = { 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f };
int key_choice = 0;

void print_state(uint64_t state[5]) {
	for (int i = 0; i < 5; i++) printf("%lx\n", state[i]);
}
void add_constant(uint64_t state[5], int i, int a) {
	state[2] = state[2] ^ constants[12 - a + i];
}
void sbox(uint64_t x[5]) {
	x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1];
	t[0] = x[0]; t[1] = x[1]; t[2] = x[2]; t[3] = x[3]; t[4] = x[4];
	t[0] = ~t[0]; t[1] = ~t[1]; t[2] = ~t[2]; t[3] = ~t[3]; t[4] = ~t[4];
	t[0] &= x[1]; t[1] &= x[2]; t[2] &= x[3]; t[3] &= x[4]; t[4] &= x[0];
	x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3]; x[3] ^= t[4]; x[4] ^= t[0];
	x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] = ~x[2];
}
uint64_t rotate(uint64_t x, int l) {
	uint64_t temp;
	temp = (x >> l) ^ (x << (64 - l));
	return temp;
}

void linear(uint64_t state[5]) {
	uint64_t temp0, temp1;
	temp0 = rotate(state[0], 19);
	temp1 = rotate(state[0], 28);
	state[0] ^= temp0 ^ temp1;
	temp0 = rotate(state[1], 61);
	temp1 = rotate(state[1], 39);
	state[1] ^= temp0 ^ temp1;
	temp0 = rotate(state[2], 1);
	temp1 = rotate(state[2], 6);
	state[2] ^= temp0 ^ temp1;
	temp0 = rotate(state[3], 10);
	temp1 = rotate(state[3], 17);
	state[3] ^= temp0 ^ temp1;
	temp0 = rotate(state[4], 7);
	temp1 = rotate(state[4], 41);
	state[4] ^= temp0 ^ temp1;
}
void p(uint64_t state[5], int a) {
	for (int i = 0; i < a; i++) {
		add_constant(state, i, a);
		sbox(state);
		linear(state);
	}
}
void initialization(uint64_t state[5], uint64_t key[2]) {
	p(state, 12);
	state[3] ^= key[0];
	state[4] ^= key[1];
}
void encrypt(uint64_t state[5], int length, uint64_t plaintext[], uint64_t ciphertext[]) {
	ciphertext[0] = plaintext[0] ^ state[0];
	for (int i = 1; i < length; i++) {
		p(state, 6);
		ciphertext[i] = plaintext[i] ^ state[0];
		state[0] = plaintext[i] ^ state[0];
	}
}
void decrypt(uint64_t state[5], int length, uint64_t plaintext[], uint64_t ciphertext[]) {
	ciphertext[0] = plaintext[0] ^ state[0];
	for (int i = 1; i < length; i++) {
		p(state, 6);
		ciphertext[i] = plaintext[i] ^ state[0];
		state[0] = plaintext[i];
	}
}
void main() {
	uint64_t IV = 0x80400c0600000000, key[2] = {0}, nonce[2] = { 0 };
	uint64_t plaintext[1] = { 0 }, ciphertext[1];
	state[0] = IV;
	state[1] = key[0];
	state[2] = key[1];
	state[3] = nonce[0];
	state[4] = nonce[1];
	//print_state(state); printf("\n");
	//p(state, 12);
	initialization(state, key);
	//print_state(state);
	encrypt(state, 1, plaintext, ciphertext); printf("\n");
	for (int i = 0; i < 1; i++) printf("%lx\n", ciphertext[i]);
	state[0] = IV;
	state[1] = key[0];
	state[2] = key[1];
	state[3] = nonce[0];
	state[4] = nonce[1]; printf("\n");
	//print_state(state); printf("\n");
	//p(state, 12);
	//initialization(state, key);
	//print_state(state);
	//decrypt(state, 10, ciphertext, plaintext); printf("\n");
	//for (int i = 0; i < 10; i++) printf("%lx\n", plaintext[i]);
}