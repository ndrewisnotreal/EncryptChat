FlowerChat - Aplikasi Chat dengan Enkripsi RSA
================================================

Panduan instalasi dan penggunaan aplikasi ini di lingkungan lokal Anda.

------------------------------------------------------------
PERSYARATAN
------------------------------------------------------------
Pastikan Anda sudah menginstall:
- Python 3.6 atau yang lebih baru
- pip (package installer untuk Python)
- Git (untuk meng-clone repository)

------------------------------------------------------------
LANGKAH-LANGKAH INSTALASI
------------------------------------------------------------

1. Clone Repository
   Buka terminal atau command prompt dan jalankan:
   
       git clone https://github.com/ndrewisnotreal/EncryptChat.git
       cd EncryptChat

2. Install Dependencies
   Jalankan perintah berikut untuk menginstal dependensi:

       pip install flask
       pip install flask-socketio
       pip install pycryptodome

3. Jalankan Aplikasi
   Jalankan file utama dengan perintah:

       python app.py

4. Akses di Browser
   Buka browser dan akses aplikasi di alamat:

       http://127.0.0.1:5000

------------------------------------------------------------
CATATAN TAMBAHAN
------------------------------------------------------------
- Disarankan menggunakan virtual environment (opsional).
- Jika tersedia file requirements.txt, Anda bisa gunakan:

       pip install -r requirements.txt

------------------------------------------------------------
LISENSI
------------------------------------------------------------
Aplikasi ini dilisensikan di bawah MIT License.
© 2025 ndrewisnotreal
