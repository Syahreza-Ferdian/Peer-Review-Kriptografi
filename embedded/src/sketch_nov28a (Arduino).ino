#include <WiFi.h>
#include <HTTPClient.h>
#include <HCSR04.h>
#include <ASCON.h>

// WiFi
const char* ssid = "Wokwi-GUEST";
const char* password = "";

// Server
const char* serverUrl = "http://192.168.127.139:8000/submit.php";

// Sensor
UltraSonicDistanceSensor distanceSensor(5, 18);

// ▼ Inisialisasi AEAD ASCON-128a
ascon::aead128a aead;       // ← INI YANG VALID UNTUK LIBRARY KAMU

// Key 16 byte (128-bit)
uint8_t key[16] = {
  0x11,0x22,0x33,0x44,
  0x55,0x66,0x77,0x88,
  0x99,0xaa,0xbb,0xcc,
  0xdd,0xee,0xff,0x10
};

// Nonce 16 byte
uint8_t nonce[16];

void generateNonce() {
  for (int i = 0; i < 16; i++) {
    nonce[i] = random(0, 256);
  }
}

void setup() {
  Serial.begin(115200);

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi Tersambung!");
}

void loop() {
  float distance = distanceSensor.measureDistanceCm();
  if (distance <= 0 || distance > 400) {
    Serial.println("Sensor error.");
    delay(2000);
    return;
  }

  // Prepare plaintext
  String plain = String(distance);
  uint8_t plaintext[32];
  size_t plen = plain.length();
  memcpy(plaintext, plain.c_str(), plen);

  // Generate new nonce
  generateNonce();

  // Set key dan nonce
  aead.set_key(key, 16);
  aead.set_nonce(nonce, 16);

  // Encrypt
  uint8_t ciphertext[64];
  int clen = aead.encrypt(ciphertext, plaintext, plen, nullptr, 0);

  // Print ciphertext
  Serial.print("Cipher: ");
  for (int i = 0; i < clen; i++) {
    Serial.printf("%02X ", ciphertext[i]);
  }
  Serial.println();

  Serial.print("Nonce: ");
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02X ", nonce[i]);
  }
  Serial.println();

  // SEND TO SERVER
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.begin(serverUrl);
    http.addHeader("Content-Type", "application/x-www-form-urlencoded");

    // Cipher HEX
    String cipherHex = "";
    for (int i = 0; i < clen; i++) {
      char buff[3];
      sprintf(buff, "%02X", ciphertext[i]);
      cipherHex += buff;
    }

    // Nonce HEX
    String nonceHex = "";
    for (int i = 0; i < 16; i++) {
      char buff[3];
      sprintf(buff, "%02X", nonce[i]);
      nonceHex += buff;
    }

    String postData = "cipher=" + cipherHex + "&nonce=" + nonceHex;

    int code = http.POST(postData);
    Serial.println(code);

    if (code > 0) {
      Serial.println("Server: " + http.getString());
    }

    http.end();
  }

  delay(3000);
}
