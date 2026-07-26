import time
import sys
import os
import kriptografi # Menggunakan modul yang dipakai di app.py

def prepare_key(password_str):
    """
    Menyesuaikan panjang password agar mutlak 16 byte (128-bit)
    Sama persis dengan logika di app.py kita.
    """
    key_bytes = password_str.encode('utf-8', errors='ignore')
    if len(key_bytes) > 16:
        return key_bytes[:16]
    else:
        return key_bytes.ljust(16, b'\x00')

def main():
    print("="*60)
    print("🕵️ PENGUJIAN DICTIONARY ATTACK (KNOWN-PLAINTEXT) PADA FILE")
    print("="*60)

    # 1. BACA FILE TARGET HASIL ENKRIPSI DARI FLASK
    # Ganti dengan nama file ENCRYPTED_... yang ada di folder uploads kamu
    folder_uploads = "uploads" # Sesuaikan jika nama foldermu beda
    nama_file = "ENCRYPTED_PDF_Deid_Deidentification_Hard_8.pdf" # GANTI DENGAN FILE TARGETMU
    file_path = os.path.join(folder_uploads, nama_file)
    
    if not os.path.exists(file_path):
        print(f"[ERROR] File '{file_path}' tidak ditemukan!")
        print("Pastikan kamu sudah mengenkripsi file lewat web dan menaruh namanya dengan benar.")
        return
        
    with open(file_path, "rb") as f:
        # Kita hanya perlu 16 byte pertama (1 blok) untuk mencari '%PDF-'
        first_block = f.read(16)

    # 2. BACA FILE WORDLIST
    wordlist_filename = "wordlist.txt"
    if not os.path.exists(wordlist_filename):
        print(f"[ERROR] File '{wordlist_filename}' tidak ditemukan!")
        print("Silakan buat file wordlist.txt dan isi dengan daftar tebakan sandi.")
        return
        
    wordlist = []
    print(f"[*] Membaca kamus '{wordlist_filename}'...")
    with open(wordlist_filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            clean_word = line.strip()
            if clean_word:
                wordlist.append(clean_word)

    print(f"[*] Target File Asli : {file_path}")
    print(f"[*] Total Kata Kamus : {len(wordlist)} kata")
    print(f"[*] Ciphertext Blok 1: {first_block.hex().upper()}")
    print("[*] Memulai mesin pembongkar kata sandi...\n")

    start_time = time.time()
    attempts = 0
    found = False

    # 3. PROSES PENYERANGAN MURNI DARI KAMUS
    for word in wordlist:
        attempts += 1
        guess_key = prepare_key(word)

        # Indikator loading 
        if attempts % 50 == 0 or attempts == len(wordlist):
            sys.stdout.write(f"\r[~] Mencoba baris ke-{attempts}: '{word}'...   ")
            sys.stdout.flush()

        try:
            # Generate subkeys dan dekripsi 1 blok pertama
            K, S = kriptografi.generate_subkeys(guess_key)
            decrypted_block = kriptografi.decrypt_block(list(first_block), K, S)
            decrypted_bytes = bytearray(decrypted_block)
            
            # 4. VERIFIKASI KEBERHASILAN (Cek Magic Bytes PDF)
            if decrypted_bytes.startswith(b'%PDF-'):
                end_time = time.time()
                sys.stdout.write("\r" + " " * 60 + "\r") # Bersihkan layar loading
                print(f"\n[SUCCESS] KUNCI DITEMUKAN: '{word}'")
                print(f"[!] File terbukti merupakan dokumen PDF asli.")
                print(f"[!] Jumlah Tebakan Kamus : {attempts} kali")
                print(f"[!] Waktu Komputasi      : {end_time - start_time:.4f} detik")
                found = True
                break
        except Exception:
            pass # Abaikan jika gagal dekripsi (out of range / garbage)

    if not found:
        print("\n\n[FAILED] Serangan gagal. Kunci tidak ada di dalam wordlist.")
        print(f"Waktu yang dihabiskan: {time.time() - start_time:.4f} detik")

if __name__ == "__main__":
    main()