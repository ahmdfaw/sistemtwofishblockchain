import json
from web3 import Web3
import solcx

# 1. Instal compiler Solidity (Hanya perlu dijalankan sekali)
print("1. Menginstal compiler Solidity (Tunggu sebentar)...")
solcx.install_solc('0.8.0')

# 2. Membaca dan mengompilasi file Smart Contract
print("2. Mengompilasi Smart Contract...")
with open("SistemSkripsiPDF.sol", "r") as file:
    contract_file = file.read()

compiled_sol = solcx.compile_standard(
    {
        "language": "Solidity",
        "sources": {"SistemSkripsiPDF.sol": {"content": contract_file}},
        "settings": {
            "outputSelection": {
                "*": {"*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]}
            }
        },
    },
    solc_version="0.8.0",
)

# Mengambil Bytecode (Bahasa Mesin) dan ABI (Buku Panduan Interaksi)
bytecode = compiled_sol["contracts"]["SistemSkripsiPDF.sol"]["SistemSkripsiPDF"]["evm"]["bytecode"]["object"]
abi = compiled_sol["contracts"]["SistemSkripsiPDF.sol"]["SistemSkripsiPDF"]["abi"]

# 3. Menghubungkan ke Ganache Lokal
# PENTING: Cek aplikasi Ganache kamu. Apakah RPC SERVER-nya 7545 atau 8545? 
ganache_url = "http://127.0.0.1:7545" 
w3 = Web3(Web3.HTTPProvider(ganache_url))

# Pastikan berhasil terhubung
if w3.is_connected():
    print("3. BERHASIL terhubung ke jaringan Ganache!")
else:
    print("GAGAL terhubung ke Ganache. Pastikan aplikasi Ganache sudah menyala.")
    exit()

# 4. Mengatur Akun (Kita gunakan akun ke-1 dari Ganache sebagai Manajer)
my_address = w3.eth.accounts[0]

# 5. Proses Deploy (Menanam Brankas ke Blockchain)
print("4. Sedang mendeploy kontrak ke Blockchain Ganache...")
SistemSkripsiPDF = w3.eth.contract(abi=abi, bytecode=bytecode)

# Membuat transaksi dari akun pertama
tx_hash = SistemSkripsiPDF.constructor().transact({'from': my_address})

# Menunggu transaksi selesai diproses oleh Ganache
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

print("\nBrankas Blockchain Berhasil Berdiri.")
print("=====================================================")
print(f"Alamat Kontrak : {tx_receipt.contractAddress}")
print("=====================================================")