#include <SPI.h>
#include <LoRa.h>

// ASCON Libs
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// --- LoRa
#define LORA_SCK 14   // GPIO14 (D5) - SCK
#define LORA_MISO 12  // GPIO12 (D6) - MISO
#define LORA_MOSI 13  // GPIO13 (D7) - MOSI
#define LORA_SS 15    // GPIO15 (D8) - SS
#define LORA_RST 4    // GPIO4 (D2) - RST
#define LORA_DI0 5    // GPIO5 (D1) - DI0
// ----

// --- ASCON 128
#define MAX_STRING_LENGTH 500
#define KEY_SIZE 128
#define NONCE_SIZE 64
#define BLOCK_SIZE 64
#define A 12
#define B 6

#define RROTATE(state, l) ((state >> l) ^ (state << (64 - l))) // ROTATE right

uint8_t constants[] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b}; // adding constants


char *encrypt(char *plaintext, char *associated, char *key, char *nonce);
char *decrypt(char *ciphertext, char *associated, char *key, char *nonce);

char plaintext[MAX_STRING_LENGTH] = "antani";
char associated[MAX_STRING_LENGTH] = {0};

char key[17] = "antaniantani1234";
char nonce[17] = "antaniantani1234";

int stringIndex = 0;
char incomingChar;


unsigned long timeoutDuration = 5000; // Timeout duration in milliseconds
unsigned long startTime; // Variable to store the start time of the operation

bool isTimedOut() {
  // Calculate the current duration of the operation
  unsigned long currentDuration = millis() - startTime;

  // Check if the current duration exceeds the timeout duration
  return currentDuration >= timeoutDuration;
}

void setup() {
  Serial.begin(9600);
  while (!Serial);

  LoRa.setPins(LORA_SS, LORA_RST, LORA_DI0);

  if (!LoRa.begin(433E6)) { // Change frequency to 433 MHz
    Serial.println("LoRa init failed. Check your connections.");
    while (1);
  }

  Serial.println("LoRa init succeeded.");

  Serial.println("Listening for packets...");

}

void loop() {
  // Send a packet
  char receivedPayload[MAX_STRING_LENGTH];
  int packetIndex = 0;

  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    Serial.print("\n\nReceived packet: ");

    // Read packet
    while (LoRa.available()) {
      receivedPayload[packetIndex++] = (char)LoRa.read(); // Read and store each character
    }
    receivedPayload[packetIndex] = '\0'; // Null-terminate the string
    Serial.println(receivedPayload);

    char *m = decrypt(receivedPayload, associated, key, nonce);
    Serial.print("Received decrypted message: ");
    Serial.println(m);
    String received = String(m);
    String receivedNonce = received.substring(0, 16);
    if (receivedNonce.equals(String(nonce))) {
      delay(1000);
      LoRa.beginPacket();
      LoRa.print(encrypt("ok", associated, key, nonce));
      LoRa.endPacket();
      Serial.println("ACK sent!");
      Serial.println("Listening for packets...");
      *nonce += 1;
    }
    free(m);
  }
}

void printState(uint64_t *state)
{

  Serial.println("\n");
  for (int i = 0; i < 5; i++)
  {
    Serial.print("x");
    Serial.print(i);
    Serial.print(": ");
    Serial.print((uint32_t)state[i] >> 32, HEX);
    Serial.print((uint32_t)state[i], HEX);
    Serial.print("\n");
  }
  Serial.print("\n");
}

uint16_t getNumBlocks(char *data)
{
  uint16_t numblocks = (strlen(data) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
  return numblocks;
}

uint64_t *splitDataIn64bitBlock(char *data) // split data in 64 bit blocks and add padding
{
  uint16_t len = strlen(data);
  uint16_t num_blocks = (len + sizeof(uint64_t) - 1) / sizeof(uint64_t); // round up
  uint64_t *blocks = (uint64_t *)calloc(num_blocks, sizeof(uint64_t));

  memcpy(blocks, data, strlen(data));
  if (len % 8)
  {
    blocks[num_blocks - 1] |= (1ULL << (len * 8 % BLOCK_SIZE));
  }

  return blocks;
}

char *getStringFrom64bitBlocks(uint64_t *blocks, uint16_t strLength)
{
  char *res = (char *)calloc(strLength + 1, sizeof(char));
  // copy elements from ciphertextInBlocks to ciphertext

  memcpy(res, blocks, strLength);
  res[strLength] = '\0';

  return res;
}

int cceil(double x)
{
  int int_part = (int)x; // Extract the integer part

  if (x == (double)int_part)
  { // If x is already an integer
    return x; // Return x
  }
  else if (x < 0)
  { // If x is negative
    return int_part; // Return the integer part
  }
  else
  { // If x is positive
    return int_part + 1; // Return the integer part + 1
  }
}

uint16_t stringLengthFromB64(const char *base64_str)
{
  int base64_len = strlen(base64_str);
  int padding = 0;

  // Check for padding characters at the end of the Base64 string
  if (base64_str[base64_len - 1] == '=')
  {
    padding++;
    if (base64_str[base64_len - 2] == '=')
    {
      padding++;
    }
  }

  // Calculate the number of bytes represented by the Base64 string
  uint64_t num_bytes = (int)cceil((6.0 * base64_len) / 8.0) - padding;

  return num_bytes;
}

char *base64_encode(const unsigned char *data, size_t input_length)
{
  const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  uint64_t output_length = 4 * ((input_length + 2) / 3);
  char *encoded_data = (char *) malloc(output_length + 1);
  if (encoded_data == NULL)
    return NULL;

  for (uint64_t i = 0, j = 0; i < input_length;)
  {
    uint32_t octet_a = i < input_length ? data[i++] : 0;
    uint32_t octet_b = i < input_length ? data[i++] : 0;
    uint32_t octet_c = i < input_length ? data[i++] : 0;

    uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

    encoded_data[j++] = base64_table[(triple >> 18) & 0x3F];
    encoded_data[j++] = base64_table[(triple >> 12) & 0x3F];
    encoded_data[j++] = base64_table[(triple >> 6) & 0x3F];
    encoded_data[j++] = base64_table[triple & 0x3F];
  }

  for (uint64_t i = 0; i < (3 - (input_length % 3)) % 3; i++)
  {
    encoded_data[output_length - 1 - i] = '=';
  }

  encoded_data[output_length] = '\0';
  return encoded_data;
}

char *base64_decode(const char *data)
{
  uint16_t in_len = strlen(data);
  uint16_t out_len = stringLengthFromB64(data);
  char *decoded_data = (char *) malloc(out_len + 1); // +1 for the null-terminator
  if (!decoded_data)
    return NULL;

  static const char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int i, j;
  for (i = 0, j = 0; i < in_len; i += 4, j += 3)
  {
    uint16_t idx[4];
    for (uint16_t k = 0; k < 4; k++)
    {
      idx[k] = strchr(b64_table, data[i + k]) - b64_table;
    }

    decoded_data[j] = ((idx[0] << 2) & 0xFC) | ((idx[1] >> 4) & 0x03);
    if (j + 1 < out_len)
      decoded_data[j + 1] = ((idx[1] << 4) & 0xF0) | ((idx[2] >> 2) & 0x0F);
    if (j + 2 < out_len)
      decoded_data[j + 2] = ((idx[2] << 6) & 0xC0) | (idx[3] & 0x3F);
  }

  decoded_data[out_len] = '\0';
  return decoded_data;
}

uint64_t *generateIV(uint8_t r, uint8_t a, uint8_t b)
{
  uint64_t *buffer = (uint64_t *)calloc(1, sizeof(uint64_t)); // 64 bit buffer
  // Generate IV
  *buffer = ((((((*buffer | 128) << 8) | r) << 8) | a) << 8 | b) << 32; //  k || r || a || b || 0^{160-k}
  return buffer;
}

uint64_t *generateEntranceState(uint64_t *K, uint64_t *N) // 128 bit key, 128 bit nonce
{
  uint64_t *state = (uint64_t *)calloc(5, sizeof(uint64_t)); // 320 bit state

  state[0] = *generateIV(BLOCK_SIZE, A, B); // first 64 bits of IV
  state[1] = K[0];                          // first 64 bits of key
  state[2] = K[1];                          // last 64 bits of key
  state[3] = N[0];                          // first 64 bits of nonce
  state[4] = N[1];                          // last 64 bits of nonce
  // S = IV || K || N
  //printState(state);
  return state; // and that's it
}

uint64_t *doPermutation(uint64_t *state, uint8_t roundNumber, uint8_t type)
{
  uint64_t temp[5] = {0};                                   // temporary state to build the sbox
  if (type == 0)                                            // a-type round
    state[2] ^= (uint64_t)constants[roundNumber];         // add round constant to key
  else                                                      // b-type round
    state[2] ^= (uint64_t)constants[roundNumber + A - B]; // add round constant to key

  // Substitution layer
  // Here, i'm building the 5 bit state from the 64 bit state, this has to be done for each 64 5 bit groups
  state[0] ^= state[4];
  state[4] ^= state[3];
  state[2] ^= state[1];
  temp[0] = state[0];
  temp[1] = state[1];
  temp[2] = state[2];
  temp[3] = state[3];
  temp[4] = state[4];
  temp[0] = ~temp[0];
  temp[1] = ~temp[1];
  temp[2] = ~temp[2];
  temp[3] = ~temp[3];
  temp[4] = ~temp[4];
  temp[0] &= state[1];
  temp[1] &= state[2];
  temp[2] &= state[3];
  temp[3] &= state[4];
  temp[4] &= state[0];
  state[0] ^= temp[1];
  state[1] ^= temp[2];
  state[2] ^= temp[3];
  state[3] ^= temp[4];
  state[4] ^= temp[0];
  state[1] ^= state[0];
  state[0] ^= state[4];
  state[3] ^= state[2];
  state[2] = ~state[2];

  // Permutation layer
  state[0] ^= RROTATE(state[0], 19) ^ RROTATE(state[0], 28);
  state[1] ^= RROTATE(state[1], 61) ^ RROTATE(state[1], 39);
  state[2] ^= RROTATE(state[2], 1) ^ RROTATE(state[2], 6);
  state[3] ^= RROTATE(state[3], 10) ^ RROTATE(state[3], 17);
  state[4] ^= RROTATE(state[4], 7) ^ RROTATE(state[4], 41);

  return state;
}

uint64_t *pbox(uint64_t *state, uint8_t roundNumber, uint8_t type)
{
  for (int i = 0; i < roundNumber; i++)
  {
    state = doPermutation(state, i, type);
  }
  return state;
}

uint64_t *initialization(uint64_t *key, uint64_t *nonce) // initialization phase in cipher diagram
{
  uint64_t *state = generateEntranceState(key, nonce);

  //printState(state);

  state = pbox(state, A, 0);
  state[3] ^= key[0];
  state[4] ^= key[1];

  return state;
}

uint64_t *processAssociated(char *associated, uint64_t *state)
{
  uint64_t *blockAssociated = splitDataIn64bitBlock(associated);
  uint16_t numBlocks = (strlen(associated) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
  if (numBlocks == 1) // if there is only one associated data block
  {
    // printf("only associated data block 0\n");
    state[0] ^= blockAssociated[0];
    pbox(state, B, 1); // pboxing, as the diagram shows
    // printState(state);
  }
  else
  {
    for (uint16_t i = 0; i < numBlocks; i++)
    { // for each generated associated data block
      // printf("Associated data block %d\n", i);
      state[0] ^= blockAssociated[i]; // xoring the associated date
      pbox(state, B, 1);              // pboxing, as the diagram shows
      // printState(state);
    }
  }
  state[4] ^= 1ULL; // final xor with 0*||1
  return state;
}

char *encrypt(char *plaintext, char *associated, char *key, char *nonce)
{
  char *ciphertext;
  uint64_t *blockKey = splitDataIn64bitBlock(key);
  uint64_t *blockNonce = splitDataIn64bitBlock(nonce);


  // INITIALIZATION
  uint64_t *state = initialization(blockKey, blockNonce);

  // ASSOCIATED DATA MANAGEMENT
  if (strlen(associated))
  { // if there is any associated date
    state = processAssociated(associated, state);
  }

  // ENCRYPTION
  uint16_t plaintextLength = strlen(plaintext);
  uint64_t *plaintextInBlocks = splitDataIn64bitBlock(plaintext);
  uint16_t plaintext_numblocks = getNumBlocks(plaintext);
  uint64_t *ciphertextInBlocks = (uint64_t *)calloc(plaintext_numblocks, sizeof(uint64_t));

  for (int i = 0; i < plaintext_numblocks; i++)
  { // as many rounds as the number of blocks
    ciphertextInBlocks[i] = plaintextInBlocks[i] ^ state[0]; // xoring plaintext and first block of state
    state[0] = ciphertextInBlocks[i];                        // state is updated
    if (i < plaintext_numblocks - 1)
    { // process after last block is different
      //printf("permutation!\n");
      pbox(state, B, 1); // state goes through the p-box
    }
    // printState(state);
  }

  ciphertext = getStringFrom64bitBlocks(ciphertextInBlocks, plaintextLength);
  ciphertext = base64_encode((const unsigned char *)ciphertext, plaintextLength);
  Serial.println("ciphertext length> ");
  Serial.println(plaintextLength);

  // FINALIZATION

  // todo
  return ciphertext;
}

char *decrypt(char *ciphertext, char *associated, char *key, char *nonce)
{

  char *plaintext;
  uint64_t *blockKey = splitDataIn64bitBlock(key);
  uint64_t *blockNonce = splitDataIn64bitBlock(nonce);

  // INITIALIZATION
  uint64_t *state = initialization(blockKey, blockNonce);

  // ASSOCIATED DATA MANAGEMENT
  if (strlen(associated))
  { // if there is any associated date
    //printf("associated data!!!\n");
    state = processAssociated(associated, state);
  }

  // DECRYPTION
  uint16_t ciphertextLength = stringLengthFromB64(ciphertext);

  ciphertext = base64_decode(ciphertext);
  printf("ciphertext length: %d\n", ciphertextLength);
  uint64_t *ciphertextInBlocks = splitDataIn64bitBlock(ciphertext);
  uint16_t ciphertext_numblocks = getNumBlocks(ciphertext);
  uint64_t *plaintextInBlocks = (uint64_t *)calloc(ciphertext_numblocks, sizeof(uint64_t));

  for (int i = 0; i < ciphertext_numblocks; i++)
  { // as many rounds as the number of blocks
    plaintextInBlocks[i] = ciphertextInBlocks[i] ^ state[0]; // xoring plaintext and first block of state
    state[0] = ciphertextInBlocks[i];                        // state is updated
    if (i < ciphertext_numblocks - 1)
    { // process after last block is different
      pbox(state, B, 1); // state goes through the p-box
    }
  }

  plaintext = getStringFrom64bitBlocks(plaintextInBlocks, ciphertextLength);

  // FINALIZATION
  // todo
  return plaintext;
}
