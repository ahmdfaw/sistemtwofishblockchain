# Sistem Twofish Blockchain

Project ini adalah aplikasi Flask untuk enkripsi dan verifikasi dokumen PDF menggunakan implementasi Twofish custom serta penyimpanan hash ke smart contract pada jaringan Ganache lokal.

## Persiapan Virtual Environment

Buat virtual environment standar Python:

```powershell
python -m venv .venv
```

Aktifkan virtual environment di Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Jika PowerShell menolak eksekusi script aktivasi, jalankan PowerShell sebagai user biasa lalu gunakan:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Setelah aktif, install dependency:

```powershell
python -m pip install -r requirements.txt
```

## Konfigurasi Environment

Buat file `.env` di root project dan isi konfigurasi Ganache serta alamat kontrak:

```env
GANACHE_URL=http://127.0.0.1:7545
CONTRACT_ADDRESS=alamat_contract_anda
```

File `.env` tidak disimpan ke git karena berisi konfigurasi lokal.

## Menjalankan Aplikasi

Pastikan Ganache sudah berjalan, virtual environment sudah aktif, dan dependency sudah terpasang. Jalankan aplikasi:

```powershell
python app.py
```

Aplikasi Flask akan berjalan pada alamat default:

```txt
http://127.0.0.1:5000
```

## Deploy Smart Contract

Jika perlu melakukan deploy ulang smart contract ke Ganache:

```powershell
python deploy.py
```

Salin alamat kontrak hasil deploy ke variabel `CONTRACT_ADDRESS` di file `.env`.

## Script Pengujian

Beberapa script pengujian tersedia:

```powershell
python uji_avalanche.py
python uji_bruteforce.py
python uji_hacker.py
```

Sesuaikan data target, file upload, Ganache, dan alamat kontrak sesuai kebutuhan sebelum menjalankan script pengujian tertentu.
