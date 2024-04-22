#include <SPI.h>
#include <LoRa.h>

#define LORA_SCK 14   // GPIO14 (D5) - SCK
#define LORA_MISO 12  // GPIO12 (D6) - MISO
#define LORA_MOSI 13  // GPIO13 (D7) - MOSI
#define LORA_SS 15    // GPIO15 (D8) - SS
#define LORA_RST 4    // GPIO4 (D2) - RST
#define LORA_DI0 5    // GPIO5 (D1) - DI0

void setup() {
  Serial.begin(9600);
  while (!Serial);

  LoRa.setPins(LORA_SS, LORA_RST, LORA_DI0);
  
  if (!LoRa.begin(433E6)) { // Change frequency to 433 MHz
    Serial.println("LoRa init failed. Check your connections.");
    while (1);
  }

  Serial.println("LoRa init succeeded.");

  LoRa.receive();
}

void loop() {
  int packetSize = LoRa.parsePacket(); 
  if (packetSize) {
    Serial.print("Received packet: ");
    
    // Read packet
    while (LoRa.available()) {
      Serial.print((char)LoRa.read());
    }
    
    Serial.println();
  }
}
