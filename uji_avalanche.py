import kriptografi

# Fungsi pembantu untuk menghitung perbedaan bit (Hamming Distance)
def hitung_perbedaan_bit(byte_array1, byte_array2):
    diff = 0
    for b1, b2 in zip(byte_array1, byte_array2):
        xor_result = b1 ^ b2
        diff += bin(xor_result).count('1')
    return diff

def uji_avalanche():
    print("="*50)
    print("🏔️ PENGUJIAN AVALANCHE EFFECT TWOFISH")
    print("="*50)

    # 1. PERSIAPAN DATA AWAL
    # Plaintext dan Key berukuran 16 byte (128 bit)
    plaintext_asli = bytearray(b"IniPesanRahasia1") 
    key_asli_bytes = bytearray(b"KataSandiKuat123")
    
    # Menghasilkan Subkeys
    K1, S1 = kriptografi.generate_subkeys(key_asli_bytes)
    
    # Enkripsi Asli
    ciphertext_asli = kriptografi.encrypt_block(list(plaintext_asli), K1, S1)

    # 2. SKENARIO A: UBAH 1 BIT PADA PLAINTEXT
    # Kita ubah bit terakhir dari karakter terakhir plaintext
    plaintext_ubah_1bit = bytearray(plaintext_asli)
    plaintext_ubah_1bit[-1] = plaintext_ubah_1bit[-1] ^ 1 # Balikkan 1 bit (XOR dengan 1)
    
    ciphertext_skenario_A = kriptografi.encrypt_block(list(plaintext_ubah_1bit), K1, S1)

    # 3. SKENARIO B: UBAH 1 BIT PADA KEY
    key_ubah_1bit = bytearray(key_asli_bytes)
    key_ubah_1bit[-1] = key_ubah_1bit[-1] ^ 1 # Balikkan 1 bit pada key
    
    K2, S2 = kriptografi.generate_subkeys(key_ubah_1bit)
    ciphertext_skenario_B = kriptografi.encrypt_block(list(plaintext_asli), K2, S2)

    # 4. PERHITUNGAN & HASIL
    total_bit_blok = 128 # 16 byte * 8 bit

    # Hitung Perbedaan
    beda_bit_A = hitung_perbedaan_bit(ciphertext_asli, ciphertext_skenario_A)
    persentase_A = (beda_bit_A / total_bit_blok) * 100

    beda_bit_B = hitung_perbedaan_bit(ciphertext_asli, ciphertext_skenario_B)
    persentase_B = (beda_bit_B / total_bit_blok) * 100

    print(f"\n[ SKENARIO A: Ubah 1 Bit pada Pesan Asli (Plaintext) ]")
    print(f"Perbedaan bit pada Ciphertext : {beda_bit_A} bit (dari {total_bit_blok} bit)")
    print(f"Persentase Avalanche Effect   : {persentase_A:.2f} %")

    print(f"\n[ SKENARIO B: Ubah 1 Bit pada Kata Sandi (Key) ]")
    print(f"Perbedaan bit pada Ciphertext : {beda_bit_B} bit (dari {total_bit_blok} bit)")
    print(f"Persentase Avalanche Effect   : {persentase_B:.2f} %")
    print("="*50)
    print("Standar yang baik (akademis) adalah mendekati 50%.")

if __name__ == "__main__":
    uji_avalanche()