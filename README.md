# Review Project Akhir Kriptografi
## Kelompok 1
- Syahreza Fisti Ferdian
- Aksamala Citrayuh Anasita
- Mirza Hilmi Shodiq

Melakukan review pada **kelompok 3**

## Dekripsi Repository
Repository ini merupakan hasil **replikasi dan peer-to-peer review** terhadap project Kelompok 3 pada mata kuliah **Kriptografi**. Project ini mensimulasikan sistem **IoT ESP32** yang mengirimkan data sensor **HC-SR04** ke backend server melalui HTTP, dengan payload yang telah dienkripsi menggunakan algoritma **ASCON**, kemudian didekripsi di server dan disimpan ke database MySQL.

## Pendekatan Review
Pada dokumentasi laporan kelompok 3, digunakan tools XAMPP dan Arduino IDE untuk proses pengembangan. Karena terdapat kendala teknis terkait XAMPP pada device reviewer, maka diputuskan untuk menggunakan pendekatan berikut untuk replikasi:

- Firmware ESP32 di-build menggunakan **PlatformIO**
- Simulasi embedded system menggunakan **Wokwi for VSCode**, bukan Wokwi versi Web Interface
- Backend server dan database (MySQL) dijalankan menggunakan **Docker & Docker Compose**

---

## 1. Penjelasan Arsitektur Sistem

Alur sistem secara umum:

1. ESP32 (simulator Wokwi) membaca jarak dari sensor HC-SR04
2. Data jarak dienkripsi menggunakan ASCON (embedded)
3. ESP32 mengirim ciphertext dan nonce ke server melalui HTTP POST
4. Server PHP memanggil script Python untuk melakukan dekripsi ASCON
5. Hasil dekripsi disimpan ke database MySQL

---

## 2. Requirements

Pastikan telah terinstall:

- **Visual Studio Code (VSCode)**
- **Docker Desktop** (Windows / Linux / Mac)
- **Git**

### Extension VSCode yang Digunakan

- PlatformIO IDE
- Wokwi for VSCode
- (Opsional) Database Client / MySQL Client

---

## 3. Setup & Build Firmware ESP32 (PlatformIO)

### 3.1 Install PlatformIO

1. Buka VSCode
2. Extensions → cari **PlatformIO IDE**
3. Install dan tunggu proses inisialisasi selesai
4. Tambahkan PlatformIO pada environment variable PATH di perangkat Anda. Untuk sistem operasi windows, path nya adalah: `C:\Users\<user-name>\.platformio\penv\Scripts`

Verifikasi instalasi pio:

```bash
pio --version
```

---

### 3.2 Informasi Konfigurasi Project Embedded

File utama konfigurasi PlatformIO berada di:

```ini
embedded/platformio.ini
```

Board yang digunakan:

```
board = esp32dev
framework = arduino
```

Library eksternal:

- HCSR04 (via PlatformIO registry). Merupakan library untuk sensor HCSR04
- ASCON (manual via ZIP di folder `ascon-lib/`)

---

### 3.3 Build Firmware

Masuk ke folder embedded:

```bash
cd embedded
```

Compile firmware:

```bash
pio run
```

Hasil build akan berada di:

```
.pio/build/esp32dev/firmware.bin
```

---

## 4. Menjalankan Backend & Database (Docker)

### 4.1 Build dan Jalankan Container

Dari root project:

```bash
docker-compose up --build -d
```

Container yang dijalankan:

- Backend PHP + Python (port 8000)
- MySQL 8.0 (port 3307)

---

### 4.2 Akses Backend

Endpoint utama:

```
http://localhost:8000/submit.php
```

Endpoint ini menerima POST request dari ESP32.

---

## 5. Menjalankan ESP32 di Wokwi

1. Buka folder `embedded/` di VSCode
2. Tekan **Ctrl + Shift + P**
3. Pilih **Wokwi: Start Simulator**

ESP32 akan otomatis:

- Terhubung ke WiFi `Wokwi-GUEST`
- Mengirim data terenkripsi ke backend

---

**Reviewer: Kelompok 1**
