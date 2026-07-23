from web3 import Web3

# 1. KONEKSI KE JARINGAN LOKAL (GANACHE)
# Sesuaikan port dengan milikmu (7545 atau 8545)
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))

if not w3.is_connected():
    print("❌ Gagal terhubung ke Ganache!")
    exit()

# 2. SETUP AKUN HACKER & TARGET KONTRAK
# Kita menggunakan akun ke-2 (index 1) sebagai hacker, bukan akun ke-1 (index 0)
hacker_account = w3.eth.accounts[1] 

# =====================================================================
# ⚠️ TUGAS: COPY-PASTE DARI app.py KAMU
# =====================================================================
contract_address = '0xB84307791934cEd3ec4E15D53e8879b6cA0AF550'

contract_abi = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"string","name":"idDokumen","type":"string"}],"name":"ambilHashDokumen","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"idDokumen","type":"string"},{"internalType":"string","name":"hashPDF","type":"string"}],"name":"simpanHashDokumen","outputs":[],"stateMutability":"nonpayable","type":"function"}]
# =====================================================================

contract = w3.eth.contract(address=contract_address, abi=contract_abi)

def mulai_serangan():
    print("="*60)
    print("🥷 SIMULASI SERANGAN HACKER PADA SMART CONTRACT")
    print("="*60)
    print(f"Alamat Hacker (Akun 2) : {hacker_account}")
    print(f"Target Smart Contract  : {contract_address}")
    print("Mencoba menyuntikkan dokumen palsu ke Blockchain...\n")

    # 3. EKSEKUSI SERANGAN
    try:
        # Hacker mencoba memanggil fungsi simpanHashDokumen secara paksa
        tx_hash = contract.functions.simpanHashDokumen(
            "SKRIPSI_PALSU_HACKER.pdf", 
            "hash_palsu_9999999999999999999"
        ).transact({'from': hacker_account})
        
        # Jika baris ini tereksekusi, berarti sistem GAGAL memblokir
        print("❌ GAWAT! Serangan Berhasil! Hacker bisa memasukkan data ke Blockchain.")
        
    except Exception as e:
        # Jika masuk ke sini, berarti sistem BERHASIL memblokir (REVERT)
        print("✅ SERANGAN BERHASIL DIBLOKIR OLEH SMART CONTRACT!")
        print(f"Pesan Error dari Ganache: \n{str(e)}")
        print("\nKesimpulan: Fitur Keamanan Hak Akses (onlyOwner) TERBUKTI AMAN secara empiris.")
    
    print("="*60)

if __name__ == "__main__":
    mulai_serangan()