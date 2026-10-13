# TUNG-128

## 1. Nama dan deskripsi program

**TUNG-128** adalah program desktop untuk mengenkripsi dan mendekripsi berkas, serta menganalisis entropi, histogram byte, dan avalanche effect pada mode ECB, CBC, CFB, OFB, dan CTR.

## 2. Teknologi yang digunakan

- Python 3.10+
- Tkinter untuk antarmuka desktop
- Modul pustaka standar Python untuk operasi berkas, statistik, dan autentikasi envelope

## 3. Dependensi

- Python 3.10 atau lebih baru dengan Tkinter tersedia. Tidak ada dependensi pihak ketiga untuk menjalankan program.
- Opsional: PyInstaller untuk membuat executable.

## 4. Tata cara menjalankan program

Jalankan perintah berikut dari direktori utama repositori:

```powershell
python app.py
```

Masukkan kunci 16 byte dalam bentuk 32 digit heksadesimal. Pilih berkas dan mode operasi. Untuk CBC, CFB, OFB, atau CTR, masukkan IV/counter 16 byte atau tekan **Generate**. Pilih **Encrypt…**, **Decrypt…**, atau **Analyze + avalanche** sesuai kebutuhan. Berkas terenkripsi menyimpan mode, IV/counter, ciphertext, dan tag integritas.

Dokumentasi fungsi API tersedia di [API Documentation](https://fajar2k5.github.io/tugas-2-if4020-kripto/).
