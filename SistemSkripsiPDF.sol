// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SistemSkripsiPDF {
    // 1. Variabel untuk menyimpan alamat Dompet Utama (Dompet A / Backend Python)
    address public owner;

    // 2. Tempat penyimpanan Hash Dokumen 
    // (Memetakan ID Dokumen ke Hash PDF)
    mapping(string => string) private documentHashes;

    // 3. TAHAP INISIALISASI (Dijalankan hanya 1 kali saat kontrak pertama kali di-deploy)
    constructor() {
        // Sistem otomatis mencatat siapa yang melakukan deploy sebagai "owner"
        owner = msg.sender; 
    }

    // 4. ATURAN PENJAGA PINTU (Modifier)
    modifier onlyOwner() {
        // Baris ini akan mengecek: "Apakah yang memanggil fungsi ini adalah si owner?"
        // Jika bukan, sistem langsung menolak dan memunculkan pesan error.
        require(msg.sender == owner, "Akses Ditolak: Anda bukan sistem resmi!");
        _; // Jika pengecekan berhasil, lanjutkan ke proses penyimpanan.
    }

    // 5. FUNGSI UNTUK MENYIMPAN HASH (Dilindungi oleh penjaga 'onlyOwner')
    function simpanHashDokumen(string memory idDokumen, string memory hashPDF) public onlyOwner {
        documentHashes[idDokumen] = hashPDF;
    }

    // 6. FUNGSI UNTUK MELIHAT HASH (Boleh diakses siapa saja untuk verifikasi)
    function ambilHashDokumen(string memory idDokumen) public view returns (string memory) {
        return documentHashes[idDokumen];
    }
}