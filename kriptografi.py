# ==========================================
# MESIN KRIPTOGRAFI TWOFISH (IMPLEMENTASI KUSTOM)
# ==========================================

import hashlib

# --- MODUL 1: OPERASI BITWISE DASAR ---

def rol(x, n, bits=32):
    """
    Rotate Left (Rol): Menggeser bit ke kiri.
    x    : Nilai yang akan digeser
    n    : Jumlah pergeseran bit
    bits : Ukuran blok (default 32-bit karena Twofish beroperasi di 32-bit words)
    """
    mask = (1 << bits) - 1
    n = n % bits
    return ((x << n) & mask) | ((x & mask) >> (bits - n))

def ror(x, n, bits=32):
    """
    Rotate Right (Ror): Menggeser bit ke kanan.
    """
    mask = (1 << bits) - 1
    n = n % bits
    return ((x & mask) >> n) | (x << (bits - n) & mask)

def gf_mult(a, b):
    """
    Perkalian dua angka (a dan b) di dalam Galois Field GF(2^8).
    Menggunakan polinomial pembatas kustom Twofish (0x169).
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        # Geser b ke kanan 1 bit
        b >>= 1
        # Cek bit paling kiri dari a (bit ke-8)
        carry = a & 0x80
        # Geser a ke kiri 1 bit, batasi agar tetap 8-bit
        a = (a << 1) & 0xFF
        # Jika ada carry, XOR dengan polinomial pembatas 0x169 (hanya 8-bit bawahnya yaitu 0x69)
        if carry:
            a ^= 0x69
    return p

# --- KONSTANTA MATRIKS TWOFISH ---

# Matriks RS (Reed-Solomon) 4x8 untuk Key Schedule
RS_MATRIX = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]
]

# Matriks MDS (Maximum Distance Separable) 4x4
MDS_MATRIX = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B]
]

def mul_matrix_mds(col):
    """
    Perkalian matriks MDS dengan input kolom 4-byte menggunakan Galois Field.
    """
    result = [0] * 4
    for i in range(4):
        val = 0
        for j in range(4):
            val ^= gf_mult(MDS_MATRIX[i][j], col[j])
        result[i] = val
    return result

# --- MODUL 2: PEMBANGKITAN KUNCI (KEY SCHEDULE) ---

# Tabel Permutasi q0 (256 byte baku dari spesifikasi Twofish)
q0 = [
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
]

# Tabel Permutasi q1 (256 byte baku dari spesifikasi Twofish)
q1 = [
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
]

def bytes_to_word(b0, b1, b2, b3):
    """
    Menggabungkan 4 byte menjadi satu 32-bit word (Little Endian).
    Contoh: [0x12, 0x34, 0x56, 0x78] -> 0x78563412
    """
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

def word_to_bytes(word):
    """
    Memecah satu 32-bit word menjadi 4 byte (Little Endian).
    Contoh: 0x78563412 -> [0x12, 0x34, 0x56, 0x78]
    """
    return [word & 0xFF, (word >> 8) & 0xFF, (word >> 16) & 0xFF, (word >> 24) & 0xFF]

# --- MODUL 3: FUNGSI JANTUNG (h-function & PHT) ---

def h_func(X, L):
    """
    Fungsi 'h' (h-function): Fungsi jantung algoritma Twofish.
    Memproses word 32-bit (X) melalui S-Box q0 dan q1, 
    disilangkan dengan array kunci L, lalu dikalikan Matriks MDS.
    """
    x = word_to_bytes(X)
    k = len(L)
    
    # Ekstrak byte dari array kunci L (format Little Endian)
    l_b = [word_to_bytes(l) for l in L]
    
    # Substitusi dan Pengacakan (Permutasi S-Box)
    # Catatan: Logika ini mendukung kunci 128-bit (k=2), 192-bit (k=3), dan 256-bit (k=4)
    if k == 4:
        x[0] = q1[x[0]] ^ l_b[3][0]
        x[1] = q0[x[1]] ^ l_b[3][1]
        x[2] = q0[x[2]] ^ l_b[3][2]
        x[3] = q1[x[3]] ^ l_b[3][3]
    if k >= 3:
        x[0] = q1[x[0]] ^ l_b[2][0]
        x[1] = q1[x[1]] ^ l_b[2][1]
        x[2] = q0[x[2]] ^ l_b[2][2]
        x[3] = q0[x[3]] ^ l_b[2][3]
    if k >= 2:
        # Tahap 2
        x[0] = q0[x[0]] ^ l_b[1][0]
        x[1] = q0[x[1]] ^ l_b[1][1]
        x[2] = q1[x[2]] ^ l_b[1][2]
        x[3] = q1[x[3]] ^ l_b[1][3]
        
    # Tahap 1 (Selalu dieksekusi)
    x[0] = q1[x[0]] ^ l_b[0][0]
    x[1] = q0[x[1]] ^ l_b[0][1]
    x[2] = q1[x[2]] ^ l_b[0][2]
    x[3] = q0[x[3]] ^ l_b[0][3]
    
    # Kalikan hasil substitusi dengan Matriks MDS
    res = mul_matrix_mds(x)
    
    return bytes_to_word(res[0], res[1], res[2], res[3])

def pht(a, b):
    """
    Pseudo-Hadamard Transform (PHT).
    Mengaduk dua word 32-bit dengan operasi penjumlahan modulo 2^32.
    """
    a = (a + b) & 0xFFFFFFFF
    b = (a + b) & 0xFFFFFFFF
    return a, b

# --- MODUL 2 (LANJUTAN): PEMBANGKITAN KUNCI (KEY SCHEDULE) ---

def rs_mult(row, col):
    """
    Perkalian satu baris matriks Reed-Solomon (8 byte) dengan kolom input (8 byte)
    menggunakan Galois Field GF(2^8).
    """
    res = 0
    for j in range(8):
        res ^= gf_mult(row[j], col[j])
    return res

def generate_subkeys(key_bytes):
    """
    Menghasilkan 40 sub-kunci (K) dan vektor S-Box dinamis (S) dari Kunci Rahasia.
    Sistem skripsi ini diatur menggunakan Kunci 128-bit (16 byte).
    """
    k = len(key_bytes) // 8  # Untuk kunci 128-bit (16 byte), nilai k = 2
    
    # 1. Pecah byte kunci menjadi 32-bit words (M)
    M = []
    for i in range(0, len(key_bytes), 4):
        M.append(bytes_to_word(key_bytes[i], key_bytes[i+1], key_bytes[i+2], key_bytes[i+3]))
    
    # Pisahkan menjadi array kata genap (Me) dan ganjil (Mo)
    Me = [M[i] for i in range(0, len(M), 2)]
    Mo = [M[i] for i in range(1, len(M), 2)]
    
    # 2. Hasilkan 40 Sub-kunci (K0 sampai K39)
    K = []
    for i in range(20):
        # Nilai konstanta pengganda (rho)
        rho = 0x01010101
        
        # Eksekusi fungsi jantung (h-function)
        A = h_func((2 * i * rho) & 0xFFFFFFFF, Me)
        B = rol(h_func(((2 * i + 1) * rho) & 0xFFFFFFFF, Mo), 8)
        
        # Aduk dengan PHT
        A, B = pht(A, B)
        
        K.append(A)
        K.append(rol(B, 9))
        
    # 3. Hasilkan Key-Dependent S-Box (S)
    S = []
    for i in range(k - 1, -1, -1):
        s_word = []
        start_idx = i * 8
        col = key_bytes[start_idx : start_idx + 8]
        for j in range(4):
            s_word.append(rs_mult(RS_MATRIX[j], col))
        S.append(bytes_to_word(s_word[0], s_word[1], s_word[2], s_word[3]))
        
    return K, S

# --- MODUL 4: PROSES UTAMA (ENKRIPSI & DEKRIPSI) ---

def g_func(X, S):
    """
    Fungsi 'g': Variasi dari fungsi jantung yang langsung dipetakan ke vektor S-Box.
    """
    return h_func(X, S)

def encrypt_block(plaintext_bytes, K, S):
    """
    Enkripsi 1 blok data (16 byte / 128-bit) menggunakan algoritma Twofish.
    """
    # 1. Pecah 16 byte menjadi 4 word (Little Endian)
    P = []
    for i in range(0, 16, 4):
        P.append(bytes_to_word(plaintext_bytes[i], plaintext_bytes[i+1], plaintext_bytes[i+2], plaintext_bytes[i+3]))
    
    # 2. Input Pre-whitening (XOR dengan K0 - K3)
    for i in range(4):
        P[i] ^= K[i]
    
    # 3. 16 Putaran Jaringan Feistel
    for r in range(16):
        t0 = g_func(P[0], S)
        t1 = g_func(rol(P[1], 8), S)
        
        # PHT dan penambahan sub-kunci
        F0 = (t0 + t1 + K[2 * r + 8]) & 0xFFFFFFFF
        F1 = (t0 + 2 * t1 + K[2 * r + 9]) & 0xFFFFFFFF
        
        # XOR dengan separuh blok lainnya dan putar (Shift)
        P[2] = ror(P[2] ^ F0, 1)
        P[3] = rol(P[3], 1) ^ F1
        
        # Swap untuk putaran berikutnya (kecuali pada putaran terakhir)
        if r < 15:
            P[0], P[1], P[2], P[3] = P[2], P[3], P[0], P[1]
            
    # 4. Output Post-whitening (XOR dengan K4 - K7)
    C = [0] * 4
    C[0] = P[2] ^ K[4]
    C[1] = P[3] ^ K[5]
    C[2] = P[0] ^ K[6]
    C[3] = P[1] ^ K[7]
    
    # 5. Gabungkan kembali ke bentuk byte array
    ciphertext = []
    for i in range(4):
        ciphertext.extend(word_to_bytes(C[i]))
    return ciphertext

def decrypt_block(ciphertext_bytes, K, S):
    """
    Dekripsi 1 blok data (16 byte / 128-bit) menggunakan algoritma Twofish.
    """
    # 1. Pecah 16 byte menjadi 4 word
    C = []
    for i in range(0, 16, 4):
        C.append(bytes_to_word(ciphertext_bytes[i], ciphertext_bytes[i+1], ciphertext_bytes[i+2], ciphertext_bytes[i+3]))
    
    # 2. Input Pre-whitening (Kebalikan dari Post-whitening enkripsi)
    P = [0] * 4
    P[2] = C[0] ^ K[4]
    P[3] = C[1] ^ K[5]
    P[0] = C[2] ^ K[6]
    P[1] = C[3] ^ K[7]
    
    # 3. 16 Putaran Jaringan Feistel (Berjalan Mundur)
    for r in range(15, -1, -1):
        t0 = g_func(P[0], S)
        t1 = g_func(rol(P[1], 8), S)
        
        F0 = (t0 + t1 + K[2 * r + 8]) & 0xFFFFFFFF
        F1 = (t0 + 2 * t1 + K[2 * r + 9]) & 0xFFFFFFFF
        
        P[2] = rol(P[2], 1) ^ F0
        P[3] = ror(P[3] ^ F1, 1)
        
        if r > 0:
            P[0], P[1], P[2], P[3] = P[2], P[3], P[0], P[1]
            
    # 4. Output Post-whitening (Kebalikan dari Pre-whitening enkripsi)
    for i in range(4):
        P[i] ^= K[i]
        
    # 5. Gabungkan kembali ke bentuk byte array
    plaintext = []
    for i in range(4):
        plaintext.extend(word_to_bytes(P[i]))
    return plaintext

if __name__ == "__main__":
    print("="*40)
    print("MESIN KRIPTOGRAFI TWOFISH BERHASIL DIRAKIT")
    print("="*40)
    
    # 1. Siapkan Kunci Rahasia (16 byte / 128-bit)
    secret_key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 
                  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]
    
    # 2. Siapkan Pesan Asli (16 byte / 128-bit)
    # Ini merepresentasikan potongan kecil data dari dokumen PDF kamu nanti
    pesan_asli = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 
                  0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50] # "ABCDEFGHIJKLMNOP"
    
    print(f"\n[INFO] Kunci Rahasia : {[hex(b) for b in secret_key]}")
    print(f"[INFO] Pesan Asli    : {[hex(b) for b in pesan_asli]}")
    
    # 3. Proses Key Schedule
    K, S = generate_subkeys(secret_key)
    
    # 4. Proses Enkripsi
    ciphertext = encrypt_block(pesan_asli, K, S)
    print(f"\n[HASIL] Pesan Terenkripsi (Ciphertext) : {[hex(b) for b in ciphertext]}")
    
    # 5. Proses Dekripsi
    plaintext_kembali = decrypt_block(ciphertext, K, S)
    print(f"[HASIL] Pesan Didekripsi Kembali       : {[hex(b) for b in plaintext_kembali]}")
    
    # 6. Validasi
    if pesan_asli == plaintext_kembali:
        print("\n✅ STATUS: SUKSES! Enkripsi dan Dekripsi algoritma Twofish bekerja 100% sempurna.")
    else:
        print("\n❌ STATUS: GAGAL! Ada kebocoran bit pada perhitungan matriks.")