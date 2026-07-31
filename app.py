import os
import hashlib
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from web3 import Web3
import kriptografi 
import time
import json
from dotenv import load_dotenv  

load_dotenv()

def hitung_perbedaan_bit(byte_array1, byte_array2):
    diff = 0
    for b1, b2 in zip(byte_array1, byte_array2):
        xor_result = b1 ^ b2
        diff += bin(xor_result).count('1')
    return diff

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ==========================================
# 🔗 KONFIGURASI WEB3 & BLOCKCHAIN (GANACHE)
# ==========================================
# [DIUBAH] Mengambil URL dari .env, default ke port 7545 jika tidak ada
ganache_url = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
w3 = Web3(Web3.HTTPProvider(ganache_url))

# [DIUBAH] Mengambil Address Kontrak dari .env (Tanpa hardcode!)
contract_address = os.getenv("CONTRACT_ADDRESS")

# ABI Standar dari SistemSkripsiPDF.sol
contract_abi = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"string","name":"idDokumen","type":"string"}],"name":"ambilHashDokumen","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"idDokumen","type":"string"},{"internalType":"string","name":"hashPDF","type":"string"}],"name":"simpanHashDokumen","outputs":[],"stateMutability":"nonpayable","type":"function"}]

# Inisialisasi Koneksi Kontrak
admin_account = None
if w3.is_connected():
    # [BARU] Pengecekan apakah contract address sudah diisi di .env
    if not contract_address:
        print("⚠️ PERINGATAN: CONTRACT_ADDRESS belum diisi di file .env!")
    else:
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)
        # Menggunakan dompet pertama di Ganache sebagai "Manajer Sistem" (owner)
        admin_account = w3.eth.accounts[0] 
        print(f"✅ Terhubung ke Blockchain! Kontrak: {contract_address}")
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
#🌐 RUTE ANTARMUKA WEB & API 
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
@app.route('/dekripsi', methods=['GET'])
@app.route('/verifikasi', methods=['GET'])
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
        twofish_trace = {}
        K, S = kriptografi.generate_subkeys(key_bytes, trace=twofish_trace)

        with open(filepath, 'rb') as f:
            pdf_data = f.read()
            padded_data = pad_data(pdf_data)

        encrypted_data = bytearray()
        cipher_asli = None
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            if i == 0:
                encrypted_block = kriptografi.encrypt_block(list(block), K, S, trace=twofish_trace)
                cipher_asli = encrypted_block
            else:
                encrypted_block = kriptografi.encrypt_block(list(block), K, S)
            encrypted_data.extend(encrypted_block)

        # ========================================================
        # 🧪 UJI AVALANCHE EFFECT (SAMPEL 1 BLOK PERTAMA DARI PDF)
        # ========================================================
        block_sampel = bytearray(padded_data[:16])

        # Skenario A: Ubah 1 bit pada File/Pesan
        block_ubah = bytearray(block_sampel)
        block_ubah[-1] = block_ubah[-1] ^ 1
        cipher_ubah_pesan = kriptografi.encrypt_block(list(block_ubah), K, S)
        beda_pesan = hitung_perbedaan_bit(cipher_asli, cipher_ubah_pesan)
        ava_pesan = round((beda_pesan / 128) * 100, 2)

        # Skenario B: Ubah 1 bit pada Kunci/Sandi
        key_ubah = bytearray(key_bytes)
        key_ubah[-1] = key_ubah[-1] ^ 1
        K2, S2 = kriptografi.generate_subkeys(key_ubah)
        cipher_ubah_key = kriptografi.encrypt_block(list(block_sampel), K2, S2)
        beda_key = hitung_perbedaan_bit(cipher_asli, cipher_ubah_key)
        ava_key = round((beda_key / 128) * 100, 2)
        # ========================================================

        encrypted_filename = "ENCRYPTED_" + filename
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_data)
            
        waktu_proses = round(time.time() - start_time, 4)
        sha256_hash = hashlib.sha256(encrypted_data).hexdigest()
        
        ukuran_kb = round(os.path.getsize(filepath) / 1024, 2)

        return jsonify({
            "status": "success",
            "filename": filename,
            "encrypted_filename": encrypted_filename,
            "hash": sha256_hash,
            "waktu": waktu_proses,
            "ava_pesan": ava_pesan, 
            "ava_key": ava_key,
            "ukuran_kb": ukuran_kb,
            "twofish_trace": twofish_trace
        })
    else:
        return jsonify({"error": "Hanya file PDF yang diizinkan!"}), 400


@app.route('/uploads/<path:filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/api/blockchain', methods=['POST'])
def api_blockchain():
    data = request.json
    filename = data.get('filename')
    encrypted_filename = data.get('encrypted_filename')
    sha256_hash = data.get('hash')
    
    ava_pesan = data.get('ava_pesan', 'N/A')
    ava_key = data.get('ava_key', 'N/A')
    ukuran_kb = data.get('ukuran_kb', '0')
    waktu_enkripsi = data.get('waktu_enkripsi', '0')

    if not w3.is_connected():
        return jsonify({"error": "Flask tidak terhubung ke Ganache!"}), 500

    try:
        start_time = time.time()
        tx_hash = contract.functions.simpanHashDokumen(filename, sha256_hash).transact({'from': admin_account})
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        waktu_simpan = round(time.time() - start_time, 4)
        txhash_str = tx_receipt.transactionHash.hex()

        simpan_ke_riwayat({
            "filename": encrypted_filename,
            "hash": sha256_hash,
            "txhash": txhash_str,
            "ava_pesan": ava_pesan, 
            "ava_key": ava_key,
            "ukuran_kb": ukuran_kb,
            "waktu_enkripsi": waktu_enkripsi,
            "waktu_simpan": waktu_simpan
        })

        return jsonify({
            "status": "success",
            "block": tx_receipt.blockNumber,
            "txhash": txhash_str,
            "gas": tx_receipt.gasUsed,
            "waktu": waktu_simpan
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/riwayat', methods=['GET'])
def api_riwayat():
    if os.path.exists(RIWAYAT_FILE):
        with open(RIWAYAT_FILE, 'r') as f:
            try:
                riwayat = json.load(f)
                return jsonify({"riwayat": riwayat})
            except:
                pass
    return jsonify({"riwayat": []})

@app.route('/api/dekripsi', methods=['POST'])
def api_dekripsi():
    try:
        if 'file_pdf' not in request.files:
            return jsonify({'error': 'Tidak ada file yang diunggah!'}), 400

        file = request.files['file_pdf']
        password = request.form.get('password')

        if not file or file.filename == '':
            return jsonify({'error': 'File belum dipilih!'}), 400

        if not password:
            return jsonify({'error': 'Kata sandi tidak boleh kosong!'}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        if filename.startswith('ENCRYPTED_'):
            id_dokumen = filename.replace('ENCRYPTED_', '', 1)
        else:
            id_dokumen = filename

        start_time = time.time()

        with open(filepath, 'rb') as f:
            encrypted_data = f.read()

        if len(encrypted_data) == 0:
            return jsonify({'error': 'File terenkripsi kosong!'}), 400

        key_bytes = prepare_key(password)
        twofish_trace = {}
        K, S = kriptografi.generate_subkeys(key_bytes, trace=twofish_trace)

        decrypted_data = bytearray()
        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i:i + 16]
            if i == 0:
                decrypted_block = kriptografi.decrypt_block(list(block), K, S, trace=twofish_trace)
            else:
                decrypted_block = kriptografi.decrypt_block(list(block), K, S)
            decrypted_data.extend(decrypted_block)

        if len(decrypted_data) == 0:
            return jsonify({'error': 'Kata sandi salah!'}), 400

        pad_len = decrypted_data[-1]

        if pad_len < 1 or pad_len > 16 or pad_len > len(decrypted_data):
            return jsonify({'error': 'KATA SANDI SALAH! Gagal membuka enkripsi dokumen.'}), 400

        decrypted_data_unpadded = decrypted_data[:-pad_len]

        if not decrypted_data_unpadded.startswith(b'%PDF-'):
            return jsonify({'error': 'KATA SANDI SALAH! File hasil dekripsi bukan dokumen PDF yang valid.'}), 400

        decrypted_filename = 'DECRYPTED_' + id_dokumen
        decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)

        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data_unpadded)

        waktu_proses = round(time.time() - start_time, 4)

        return jsonify({
            'status': 'success',
            'pesan': 'Dekripsi PDF Berhasil!',
            'decrypted_filename': decrypted_filename,
            'waktu': waktu_proses,
            'twofish_trace': twofish_trace
        })

    except Exception as e:
        return jsonify({
            'error': f'Gagal melakukan proses dekripsi: {str(e)}'
        }), 500


@app.route('/api/verifikasi', methods=['POST'])
def api_verifikasi():
    try:
        if 'file_pdf' not in request.files:
            return jsonify({'error': 'Tidak ada file yang diunggah!'}), 400

        file = request.files['file_pdf']

        if not file or file.filename == '':
            return jsonify({'error': 'File belum dipilih!'}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        if filename.startswith('ENCRYPTED_'):
            id_dokumen = filename.replace('ENCRYPTED_', '', 1)
        else:
            id_dokumen = filename

        start_time = time.time()

        with open(filepath, 'rb') as f:
            file_data = f.read()

        if len(file_data) == 0:
            return jsonify({'error': 'File kosong!'}), 400

        sha256_hash = hashlib.sha256(file_data).hexdigest()

        if not w3.is_connected():
            return jsonify({'error': 'Flask tidak terhubung ke Ganache!'}), 500

        hash_di_blockchain = contract.functions.ambilHashDokumen(id_dokumen).call()

        if not hash_di_blockchain:
            return jsonify({
                'error': f"Dokumen '{id_dokumen}' tidak ditemukan dalam catatan Blockchain!",
                'hash_file': sha256_hash,
                'hash_blockchain': None
            }), 404

        waktu_proses = round(time.time() - start_time, 4)

        if sha256_hash != hash_di_blockchain:
            return jsonify({
                'status': 'mismatch',
                'error': 'INTEGRITAS GAGAL! Hash file tidak cocok dengan catatan Blockchain. File telah dimanipulasi/palsu!',
                'hash_file': sha256_hash,
                'hash_blockchain': hash_di_blockchain,
                'waktu': waktu_proses
            }), 400

        return jsonify({
            'status': 'success',
            'pesan': 'INTEGRITAS VALID! Hash dokumen cocok dengan catatan Blockchain. Dokumen asli dan belum dimanipulasi.',
            'hash_file': sha256_hash,
            'hash_blockchain': hash_di_blockchain,
            'waktu': waktu_proses
        })

    except Exception as e:
        return jsonify({
            'error': f'Gagal melakukan proses verifikasi blockchain: {str(e)}'
        }), 500
    
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
