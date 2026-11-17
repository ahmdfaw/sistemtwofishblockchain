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
    print("PENGUJIAN DICTIONARY ATTACK (KNOWN-PLAINTEXT) PADA FILE")
    print("="*60)

    # 1. BACA FILE TARGET HASIL ENKRIPSI DARI FLASK
    if len(sys.argv) < 2:
        print("[ERROR] Masukkan minimal 1 nama file target yang ingin diuji!")
        print("Cara penggunaan: python uji_bruteforce.py <nama_file1.pdf> [nama_file2.pdf] ...")
        print("Contoh: python uji_bruteforce.py ENCRYPTED_Data_Uji_1.pdf")
        return

    folder_uploads = "uploads" # Sesuaikan jika nama foldermu beda
    target_files = sys.argv[1:] # Mengambil semua argumen setelah nama script
    targets_data = {} # Dictionary untuk menyimpan nama_file -> 16 byte pertama
    
    print("[*] Memeriksa file target...")
    for nama_file in target_files:
        file_path = os.path.join(folder_uploads, nama_file)
        if not os.path.exists(file_path):
            print(f"  [-] [ERROR] File '{nama_file}' tidak ditemukan, dilewati.")
            continue
            
        with open(file_path, "rb") as f:
            # Kita hanya perlu 16 byte pertama (1 blok) untuk mencari '%PDF-'
            targets_data[nama_file] = f.read(16)
            print(f"  [+] [OK] File '{nama_file}' dimuat.")
            
    if not targets_data:
        print("\n[ERROR] Tidak ada file target yang valid untuk diuji.")
        return

    # 2. BACA FILE WORDLIST
    wordlist_filename = "wordlist2.txt"
    if not os.path.exists(wordlist_filename):
        print(f"\n[ERROR] File '{wordlist_filename}' tidak ditemukan!")
        print("Silakan buat file wordlist.txt dan isi dengan daftar tebakan sandi.")
        return
        
    wordlist = []
    print(f"\n[*] Membaca kamus '{wordlist_filename}'...")
    with open(wordlist_filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            clean_word = line.strip()
            if clean_word:
                wordlist.append(clean_word)

    print(f"[*] Total Kata Kamus : {len(wordlist)} kata")
    print(f"[*] Total Target Uji : {len(targets_data)} file")
    print("[*] Memulai mesin pembongkar kata sandi...\n\n")

    start_time = time.time()
    attempts = 0
    found_targets = []
    total_targets = len(targets_data)

    # 3. PROSES PENYERANGAN MURNI DARI KAMUS
    for word in wordlist:
        attempts += 1
        guess_key = prepare_key(word)

        # Indikator loading 
        if attempts % 500 == 0 or attempts == len(wordlist):
            sys.stdout.write(f"\r[~] Mencoba baris ke-{attempts}: '{word}'...         ")
            sys.stdout.flush()

        try:
            # Generate subkeys (cukup 1x per kata untuk semua target)
            K, S = kriptografi.generate_subkeys(guess_key)
        except Exception:
            continue # Abaikan jika key preparation gagal

        # Coba dekripsi ke semua target yang belum ditemukan kuncinya
        targets_to_test = [t for t in targets_data.keys() if t not in found_targets]
        for t_name in targets_to_test:
            try:
                decrypted_block = kriptografi.decrypt_block(list(targets_data[t_name]), K, S)
                decrypted_bytes = bytearray(decrypted_block)
                
                # 4. VERIFIKASI KEBERHASILAN (Cek Magic Bytes PDF)
                if decrypted_bytes.startswith(b'%PDF-'):
                    end_time = time.time()
                    sys.stdout.write("\r" + " " * 80 + "\r") # Bersihkan layar loading agar tidak tumpang tindih
                    print(f"[SUCCESS] KUNCI DITEMUKAN UNTUK: '{t_name}'")
                    print(f"  => Kata Sandi : '{word}'")
                    print(f"  => Tebakan Ke : {attempts} kali")
                    print(f"  => Waktu      : {end_time - start_time:.4f} detik\n")
                    found_targets.append(t_name)
            except Exception:
                pass # Abaikan jika gagal dekripsi (out of range / garbage)
                
        # Jika semua target sudah ketemu, tidak perlu lanjut membaca wordlist
        if len(found_targets) == total_targets:
            break

    print("\n") # Memberikan jarak antara indikator loading terakhir dan hasil summary
    if len(found_targets) < total_targets:
        print("[FAILED] Serangan selesai. Beberapa/semua target tidak ditemukan kuncinya:")
        for t_name in targets_data.keys():
            if t_name not in found_targets:
                print(f"  - {t_name}")
        print(f"\nWaktu total yang dihabiskan: {time.time() - start_time:.4f} detik")
    else:
        print("[SUCCESS] Serangan selesai. Seluruh file target berhasil ditemukan kuncinya!")
        print(f"\nWaktu total yang dihabiskan: {time.time() - start_time:.4f} detik")

if __name__ == "__main__":
    main()