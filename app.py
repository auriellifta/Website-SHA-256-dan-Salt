import sqlite3
import time
import secrets  # Untuk menghasilkan 32 karakter hex salt acak kriptografi
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_NAME = "rekam_medis.db"
LOCKOUT_DURATION = 5 * 60  # Durasi blokir dikunci ke 5 menit (300 detik)

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def ror(x, n): return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
def sha256_manual(message):
    if isinstance(message, str): message = message.encode('utf-8')
    h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    ml = len(message) * 8
    message += b'\x80'
    while (len(message) * 8) % 512 != 448: message += b'\x00'
    message += ml.to_bytes(8, 'big')
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = [0] * 64
        for j in range(16): w[j] = int.from_bytes(chunk[j*4:j*4+4], 'big')
        for j in range(16, 64):
            s0 = ror(w[j-15], 7) ^ ror(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = ror(w[j-2], 17) ^ ror(w[j-2], 19) ^ (w[j-2] >> 10)
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xFFFFFFFF
        a, b, c, d, e, f, g, hh = h
        for j in range(64):
            S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (hh + S1 + ch + K[j] + w[j]) & 0xFFFFFFFF
            S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            hh, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
        for j, val in enumerate([a, b, c, d, e, f, g, hh]):
            h[j] = (h[j] + val) & 0xFFFFFFFF
    return ''.join(f'{x:08x}' for x in h)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    conn.execute('''CREATE TABLE IF NOT EXISTS staf_klinik (
                        username TEXT PRIMARY KEY,
                        salt TEXT,
                        password_hash TEXT,
                        failed_attempts INTEGER DEFAULT 0,
                        locked_until REAL)''')
    conn.commit()
    conn.close()

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username, password = data.get('username'), data.get('password')
    
    # 32 karakter Hexadesimal acak murni
    salt = secrets.token_hex(16) 
    # Menggunakan rumus: salt + password sesuai keinginan Anda
    pwd_hash = sha256_manual(salt + password)
    
    conn = sqlite3.connect(DB_NAME)
    try:
        conn.execute("INSERT INTO staf_klinik (username, salt, password_hash) VALUES (?, ?, ?)", (username, salt, pwd_hash))
        conn.commit()
        return jsonify({"status": "success", "message": "Berhasil!"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username sudah ada!"}), 400
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username, password = data.get('username'), data.get('password')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT salt, password_hash, failed_attempts, locked_until FROM staf_klinik WHERE username=?", (username,))
    row = cursor.fetchone()
    
    if not row:
        return jsonify({"status": "error", "message": "User tidak ditemukan!"}), 404
        
    salt, db_hash, failed, locked_until = row
    current_time = time.time()
    
    if locked_until and current_time < locked_until:
        sisa = int(locked_until - current_time)
        return jsonify({"status": "error", "message": f"Akun Terblokir! Sisa waktu: {sisa} detik.", "sisa_detik": sisa}), 403
        
    # Verifikasi menggunakan urutan rumus: salt + password
    if sha256_manual(salt + password) == db_hash:
        cursor.execute("UPDATE staf_klinik SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
        conn.commit()
        return jsonify({"status": "success"})
    else:
        failed += 1
        lock = current_time + LOCKOUT_DURATION if failed >= 3 else None
        cursor.execute("UPDATE staf_klinik SET failed_attempts=?, locked_until=? WHERE username=?", (failed, lock, username))
        conn.commit()
        msg = f"Password salah! (Percobaan {failed})"
        sisa_detik = 0
        if lock: 
            msg = "Akun telah dikunci selama 5 menit!"
            sisa_detik = int(LOCKOUT_DURATION)
        return jsonify({"status": "error", "message": msg, "sisa_detik": sisa_detik}), 401

@app.route('/api/admin/users', methods=['GET'])
def get_users():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash, failed_attempts, locked_until, salt FROM staf_klinik")
    rows = cursor.fetchall()
    
    data = []
    current_time = time.time()
    for r in rows:
        locked = bool(r[3] and current_time < r[3])
        sisa = int(r[3] - current_time) if locked else 0
        data.append({
            "username": r[0], 
            "hash": r[1], 
            "failed_attempts": r[2],
            "is_blocked": locked, 
            "sisa_detik": max(0, sisa),
            "salt": r[4]
        })
    return jsonify({"status": "success", "data": data})

@app.route('/api/admin/unlock', methods=['POST'])
def unlock():
    username = request.json.get('username')
    conn = sqlite3.connect(DB_NAME)
    conn.execute("UPDATE staf_klinik SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
    conn.commit()
    return jsonify({"status": "success"})

@app.route('/api/admin/unlock_all', methods=['POST'])
def unlock_all():
    conn = sqlite3.connect(DB_NAME)
    conn.execute("UPDATE staf_klinik SET failed_attempts=0, locked_until=NULL")
    conn.commit()
    return jsonify({"status": "success"})

@app.route('/api/admin/delete', methods=['POST'])
def delete_user():
    username = request.json.get('username')
    conn = sqlite3.connect(DB_NAME)
    conn.execute("DELETE FROM staf_klinik WHERE username=?", (username,))
    conn.commit()
    return jsonify({"status": "success"})

@app.route('/api/debug', methods=['GET'])
def get_debug():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username, failed_attempts, locked_until FROM staf_klinik")
    rows = cursor.fetchall()
    out = "== SIMULASI SQLITE DATABASE ==\n"
    for r in rows:
        out += f"User: {r[0]} | Gagal: {r[1]}x | Terkunci Hingga: {r[2] if r[2] else 'NULL'}\n"
    return jsonify({"status": "success", "data": out})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)