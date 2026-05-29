// ============================================================
// 1. SHA-256 MANUAL — Implementasi bitwise murni (Tanpa Library)
// ============================================================
function sha256_manual(message) {
    const K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    let H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];

    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

    let bytes = Array.from(new TextEncoder().encode(message));
    const bitLen = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0x00);
    for (let i = 7; i >= 0; i--) bytes.push((bitLen / Math.pow(2, i * 8)) & 0xff);

    for (let off = 0; off < bytes.length; off += 64) {
        const W = [];
        for (let i = 0; i < 16; i++)
            W[i] = (bytes[off + i * 4] << 24) | (bytes[off + i * 4 + 1] << 16) | (bytes[off + i * 4 + 2] << 8) | bytes[off + i * 4 + 3];
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
            const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
        }
        let [a, b, c, d, e, f, g, h] = H;
        for (let i = 0; i < 64; i++) {
            const T1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
            const T2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
            h = g; g = f; f = e; e = (d + T1) | 0; d = c; c = b; b = a; a = (T1 + T2) | 0;
        }
        H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    return H.map(v => v.toString(16).padStart(8, '0')).join('');
}

// ============================================================
// 2. KONSTANTA CONFIG
// ============================================================
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin123';
const API_BASE   = 'http://127.0.0.1:5000/api';

function formatWaktu(detik) {
    return String(Math.floor(detik / 60)).padStart(2, '0') + ':' + String(detik % 60).padStart(2, '0');
}

let timerInterval = null;
function mulaiCountdown(sisaDetik) {
    if (timerInterval) clearInterval(timerInterval);
    const timerBox = document.getElementById('lockout-timer');
    const timerVal = document.getElementById('lockout-countdown');
    timerBox.style.display = 'block';
    let sisa = sisaDetik;
    timerVal.innerText = formatWaktu(sisa);

    timerInterval = setInterval(function () {
        sisa--;
        if (sisa <= 0) {
            clearInterval(timerInterval);
            timerBox.style.display = 'none';
            clearMsg('login-msg');
            showMsg('login-msg', 'Waktu blokir habis. Silakan coba login kembali.', 'success');
        } else {
            timerVal.innerText = formatWaktu(sisa);
        }
    }, 1000);
}

function hentikanCountdown() {
    if (timerInterval) clearInterval(timerInterval);
    const timerBox = document.getElementById('lockout-timer');
    if (timerBox) timerBox.style.display = 'none';
}

// ============================================================
// 3. NAVIGASI VIEW & REALTIME INTERVAL
// ============================================================
let adminInterval = null; // Menampung interval agar admin bisa hitung mundur berkala

function switchView(view) {
    document.getElementById('auth-wrapper').style.display      = 'none';
    document.getElementById('dashboard-section').style.display = 'none';
    document.getElementById('admin-section').style.display     = 'none';

    // Bersihkan interval jika keluar dari halaman admin
    if (adminInterval) {
        clearInterval(adminInterval);
        adminInterval = null;
    }

    if (view === 'login') {
        document.getElementById('auth-wrapper').style.display = 'flex';
        toggleAuthPanel(false);
        hentikanCountdown();
    } else if (view === 'dashboard') {
        document.getElementById('dashboard-section').style.display = 'block';
    } else if (view === 'admin') {
        document.getElementById('admin-section').style.display = 'block';
        renderTabelAdmin();
        // Menjalankan hitung mundur otomatis pada tabel admin setiap 1 detik
        adminInterval = setInterval(renderTabelAdmin, 1000);
    }
}

function showMsg(id, text, type) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = 'w-full text-sm rounded-[12px] p-3 ' + (
        type === 'error'
            ? 'bg-red-950/50 text-red-400 border border-red-500/30'
            : 'bg-green-950/50 text-green-400 border border-green-500/30'
    );
    el.innerHTML = text;
    el.style.display = 'block';
}

function clearMsg(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
}

// ============================================================
// 4. HANDLER REGISTRASI (FETCH KE PYTHON)
// ============================================================
function handleRegister() {
    const user = document.getElementById('reg-username').value.trim();
    const pass = document.getElementById('reg-password').value;

    if (!user || !pass) {
        showMsg('reg-msg', '⚠️ Semua kolom wajib diisi!', 'error');
        return;
    }
    if (user.length < 3) {
        showMsg('reg-msg', '⚠️ Username minimal 3 karakter!', 'error');
        return;
    }
    if (pass.length < 6) {
        showMsg('reg-msg', '⚠️ Password minimal 6 karakter!', 'error');
        return;
    }
    if (user === ADMIN_USER) {
        showMsg('reg-msg', '⚠️ Username tersebut sudah dicadangkan!', 'error');
        return;
    }

    fetch(`${API_BASE}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            confetti({ particleCount: 150, spread: 80, colors: ['#0ea5e9', '#ffffff', '#2563eb'] });
            document.getElementById('reg-username').value = '';
            document.getElementById('reg-password').value = '';
            clearMsg('reg-msg');
            document.getElementById('successModal').classList.add('active');
        } else {
            showMsg('reg-msg', '⚠️ ' + data.message, 'error');
        }
    })
    .catch(() => showMsg('reg-msg', '⚠️ Gagal terhubung ke server Python!', 'error'));
}

// ============================================================
// 5. HANDLER LOGIN (FETCH KE PYTHON)
// ============================================================
function handleLogin() {
    const user = document.getElementById('login-username').value.trim();
    const pass = document.getElementById('login-password').value;

    if (!user || !pass) {
        showMsg('login-msg', '⚠️ Username dan password wajib diisi!', 'error');
        return;
    }

    if (user === ADMIN_USER && pass === ADMIN_PASS) {
        switchView('admin');
        return;
    }

    fetch(`${API_BASE}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            hentikanCountdown();
            document.getElementById('user-greeting').innerText = 'Halo, ' + user;
            switchView('dashboard');
        } else {
            showMsg('login-msg', data.message, 'error');
            if (data.sisa_detik && data.sisa_detik > 0) {
                mulaiCountdown(data.sisa_detik);
            }
        }
    })
    .catch(() => showMsg('login-msg', '⚠️ Gagal terhubung ke server Python!', 'error'));
}

function handleLogout() {
    switchView('login');
}

// ============================================================
// 6. PANEL ADMIN (REALTIME TICKING FETCH)
// ============================================================
function renderTabelAdmin() {
    const tbody = document.getElementById('admin-tabel-body');
    if (!tbody) return;

    fetch(`${API_BASE}/admin/users`)
    .then(res => res.json())
    .then(resData => {
        if (resData.status !== 'success') return;
        const entries = resData.data;

        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-slate-400 dark:text-slate-500">Belum ada staf terdaftar.</td></tr>';
            return;
        }

        tbody.innerHTML = entries.map((data) => {
            let statusBadge = '';
            let aksiBtn     = `<span class="text-slate-400 dark:text-slate-600 w-[98px] text-center font-bold">—</span>`;

            if (data.is_blocked) {
                // Menampilkan hitung mundur waktu blokir secara realtime di tabel admin
                statusBadge = `<span class="bg-red-100 text-red-800 dark:bg-red-500/20 dark:text-red-400 dark:border dark:border-red-500/30 py-1 px-2.5 rounded-lg text-xs font-bold inline-flex items-center gap-1">Terblokir (${formatWaktu(data.sisa_detik)})</span>`;
                aksiBtn     = `<button onclick="adminUnlockAkun('${data.username}')" class="bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold py-1.5 px-3 rounded-lg transition flex items-center gap-1"><i class="fas fa-lock-open text-[10px]"></i> Buka Blokir</button>`;
            } else if (data.failed_attempts > 0) {
                statusBadge = `<span class="bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-400 dark:border dark:border-amber-500/30 py-1 px-2.5 rounded-lg text-xs font-bold inline-flex items-center gap-1">Gagal ${data.failed_attempts}x</span>`;
                aksiBtn     = `<button onclick="adminUnlockAkun('${data.username}')" class="bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold py-1.5 px-3 rounded-lg transition flex items-center gap-1"><i class="fas fa-lock-open text-[10px]"></i> Buka Blokir</button>`;
            } else {
                statusBadge = `<span class="bg-emerald-100 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-400 dark:border dark:border-emerald-500/30 py-1 px-2.5 rounded-lg text-xs font-bold inline-flex items-center gap-1">Aktif</span>`;
            }

            const displayHash = data.hash ? data.hash.substring(0, 20) : '—';
            const displaySalt = data.salt ? data.salt.substring(0, 16) : '—';

            return `
            <tr class="hover:bg-slate-50/60 dark:hover:bg-slate-800/20 transition-colors">
                <td class="py-4 px-5 font-bold text-slate-900 dark:text-white">${data.username}</td>
                <td class="py-4 px-5 font-mono text-xs text-slate-400 dark:text-slate-500">${displayHash}...</td>
                <td class="py-4 px-5 font-mono text-xs text-slate-400 dark:text-slate-500">${displaySalt}...</td>
                <td class="py-4 px-5">${statusBadge}</td>
                <td class="py-4 px-5">
                    <div class="flex items-center justify-end gap-2 pr-2">
                        ${aksiBtn}
                        <button onclick="adminHapusAkun('${data.username}')" class="bg-rose-500 hover:bg-rose-600 text-white p-2 rounded-lg transition flex items-center justify-center w-8 h-8 shadow-sm">
                            <i class="fas fa-trash-alt text-xs"></i>
                        </button>
                    </div>
                </td>
            </tr>`;
        }).join('');
    })
    .catch(err => console.error("Gagal memuat tabel admin:", err));
}

function adminUnlockAkun(username) {
    fetch(`${API_BASE}/admin/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') renderTabelAdmin();
    });
}

function adminUnlockSemua() {
    fetch(`${API_BASE}/admin/unlock_all`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') renderTabelAdmin();
    });
}

function adminHapusAkun(username) {
    if (!confirm(`Hapus akun "${username}"? Tindakan ini tidak dapat dibatalkan.`)) return;
    fetch(`${API_BASE}/admin/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') renderTabelAdmin();
    });
}

// ============================================================
// 7. INISIALISASI
// ============================================================
window.onload = function () {
    switchView('login');
};