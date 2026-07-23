import os
import hashlib
from flask import Flask, render_template, request
from flask import jsonify
from werkzeug.utils import secure_filename
from web3 import Web3
import kriptografi 
import time
import json

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ==========================================
# 🔗 KONFIGURASI WEB3 & BLOCKCHAIN (GANACHE)
# ==========================================
# Ganti URL ini jika Ganache milikmu menggunakan port 8545
ganache_url = "http://127.0.0.1:7545" 
w3 = Web3(Web3.HTTPProvider(ganache_url))

# TODO: MASUKKAN ALAMAT KONTRAKMU DI BAWAH INI
contract_address = "0xB84307791934cEd3ec4E15D53e8879b6cA0AF550"

# ABI Standar dari SistemSkripsiPDF.sol (Sudah diekstrak untukmu)
contract_abi = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"string","name":"idDokumen","type":"string"}],"name":"ambilHashDokumen","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"idDokumen","type":"string"},{"internalType":"string","name":"hashPDF","type":"string"}],"name":"simpanHashDokumen","outputs":[],"stateMutability":"nonpayable","type":"function"}]

# Inisialisasi Koneksi Kontrak
if w3.is_connected():
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    # Menggunakan dompet pertama di Ganache sebagai "Manajer Sistem" (owner)
    admin_account = w3.eth.accounts[0] 
else:
    print("⚠️ PERINGATAN: Flask tidak terhubung ke Ganache!")

# ==========================================
# ⚙️ FUNGSI BANTUAN KRIPTOGRAFI
# ==========================================
def pad_data(data):
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)

def prepare_key(password):
    key_bytes = password.encode('utf-8')
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\0')
    elif len(key_bytes) > 16:
        key_bytes = key_bytes[:16]
    return list(key_bytes)

#==========================================
#🌐 RUTE ANTARMUKA WEB & API (DIPERBARUI)
#==========================================
RIWAYAT_FILE = 'database_riwayat.json'

def simpan_ke_riwayat(data):
    riwayat = []
    if os.path.exists(RIWAYAT_FILE):
        with open(RIWAYAT_FILE, 'r') as f:
            try:
                riwayat = json.load(f)
            except json.JSONDecodeError:
                riwayat = []
    riwayat.append(data)
    with open(RIWAYAT_FILE, 'w') as f:
        json.dump(riwayat, f, indent=4)

@app.route('/', methods=['GET'])
def beranda():
    return render_template('index.html')

@app.route('/api/enkripsi', methods=['POST'])
def api_enkripsi():
    if 'file_pdf' not in request.files:
        return jsonify({"error": "Tidak ada file yang diunggah!"}), 400

    file = request.files['file_pdf']
    password = request.form.get('password')

    if file.filename == '':
        return jsonify({"error": "Nama file kosong!"}), 400

    if file and file.filename.endswith('.pdf'):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Proses Enkripsi Twofish
        start_time = time.time()
        key_bytes = prepare_key(password)
        K, S = kriptografi.generate_subkeys(key_bytes)

        with open(filepath, 'rb') as f:
            pdf_data = f.read()
            padded_data = pad_data(pdf_data)

        encrypted_data = bytearray()
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            encrypted_block = kriptografi.encrypt_block(list(block), K, S)
            encrypted_data.extend(encrypted_block)

        encrypted_filename = "ENCRYPTED_" + filename
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_data)
            
        waktu_proses = round(time.time() - start_time, 4)
        sha256_hash = hashlib.sha256(encrypted_data).hexdigest()

        return jsonify({
            "status": "success",
            "filename": filename,
            "encrypted_filename": encrypted_filename,
            "hash": sha256_hash,
            "waktu": waktu_proses
        })
    else:
        return jsonify({"error": "Hanya file PDF yang diizinkan!"}), 400

@app.route('/api/blockchain', methods=['POST'])
def api_blockchain():
    data = request.json
    filename = data.get('filename')
    encrypted_filename = data.get('encrypted_filename')
    sha256_hash = data.get('hash')

    if not w3.is_connected():
        return jsonify({"error": "Flask tidak terhubung ke Ganache!"}), 500

    try:
        start_time = time.time()
        tx_hash = contract.functions.simpanHashDokumen(filename, sha256_hash).transact({'from': admin_account})
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        waktu_proses = round(time.time() - start_time, 4)

        txhash_str = tx_receipt.transactionHash.hex()

        # Simpan ke riwayat JSON setelah sukses masuk blockchain
        simpan_ke_riwayat({
            "filename": encrypted_filename,
            "hash": sha256_hash,
            "txhash": txhash_str
        })

        return jsonify({
            "status": "success",
            "block": tx_receipt.blockNumber,
            "txhash": txhash_str,
            "gas": tx_receipt.gasUsed,
            "waktu": waktu_proses
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/riwayat', methods=['GET'])
def api_riwayat():
    # Membaca riwayat dari file JSON
    if os.path.exists(RIWAYAT_FILE):
        with open(RIWAYAT_FILE, 'r') as f:
            try:
                riwayat = json.load(f)
                return jsonify({"riwayat": riwayat})
            except:
                pass
    return jsonify({"riwayat": []})

@app.route('/api/verifikasi', methods=['POST'])
def api_verifikasi():
    try:
        # 1. VALIDASI INPUT FILE & PASSWORD
        if 'file_pdf' not in request.files:
            return jsonify({'error': 'Tidak ada file yang diunggah!'}), 400

        file = request.files['file_pdf']
        password = request.form.get('password')

        if not file or file.filename == '':
            return jsonify({'error': 'File belum dipilih!'}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # PINDAHKAN FILE.SAVE KE DALAM TRY AGAR JIKA PENDING/LOCKED TIDAK MEMBUAT FLASK CRASH
        file.save(filepath)

        # OTOMATISASI: Ambil ID Dokumen asli dengan menghapus prefix 'ENCRYPTED_'
        if filename.startswith('ENCRYPTED_'):
            id_dokumen = filename.replace('ENCRYPTED_', '', 1)
        else:
            id_dokumen = filename

        start_time = time.time()

        # 2. BACA FILE TERENKRIPSI & HITUNG HASH SHA-256
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()

        if len(encrypted_data) == 0:
            return jsonify({'error': 'File terenkripsi kosong!'}), 400

        sha256_hash = hashlib.sha256(encrypted_data).hexdigest()

        # 3. VERIFIKASI KE BLOCKCHAIN GANACHE
        if not w3.is_connected():
            return jsonify({'error': 'Flask tidak terhubung ke Ganache!'}), 500

        hash_di_blockchain = contract.functions.ambilHashDokumen(id_dokumen).call()

        if not hash_di_blockchain:
            return jsonify({
                'error': f"Dokumen '{id_dokumen}' tidak ditemukan dalam catatan Blockchain!"
            }), 404

        if sha256_hash != hash_di_blockchain:
            return jsonify({
                'error': 'INTEGRITAS GAGAL! Hash file tidak cocok dengan catatan Blockchain. File telah dimanipulasi/palsu!'
            }), 400

        # 4. PROSES DEKRIPSI TWOFISH
        key_bytes = prepare_key(password)
        K, S = kriptografi.generate_subkeys(key_bytes)

        decrypted_data = bytearray()
        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i:i + 16]
            decrypted_block = kriptografi.decrypt_block(list(block), K, S)
            decrypted_data.extend(decrypted_block)

        # 5. CEK KEVALIDAN KATA SANDI (PADDING & MAGIC BYTES HEADER PDF)
        if len(decrypted_data) == 0:
            return jsonify({'error': 'Kata sandi salah!'}), 400

        pad_len = decrypted_data[-1]

        # Validasi angka padding PKCS#7 (1 s/d 16)
        if pad_len < 1 or pad_len > 16 or pad_len > len(decrypted_data):
            return jsonify({'error': 'KATA SANDI SALAH! Gagal membuka enkripsi dokumen.'}), 400

        decrypted_data_unpadded = decrypted_data[:-pad_len]

        # Validasi Header PDF (Magic Bytes harus diawali %PDF-)
        if not decrypted_data_unpadded.startswith(b'%PDF-'):
            return jsonify({'error': 'KATA SANDI SALAH! File hasil dekripsi bukan dokumen PDF yang valid.'}), 400

        # Simpan file jika kata sandi & hash valid
        decrypted_filename = 'DECRYPTED_' + id_dokumen
        decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)

        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data_unpadded)

        waktu_proses = round(time.time() - start_time, 4)

        return jsonify({
            'status': 'success',
            'pesan': 'Verifikasi Valid & Dekripsi Berhasil!',
            'hash': sha256_hash,
            'decrypted_filename': decrypted_filename,
            'waktu': waktu_proses,
        })

    except Exception as e:
        # Menangkap semua error agar Flask TETAP HIDUP dan mengirim pesan ke browser
        return jsonify({
            'error': f'Gagal melakukan proses verifikasi/dekripsi: {str(e)}'
        }), 500
    
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)