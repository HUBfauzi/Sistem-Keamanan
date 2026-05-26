# ============================================================
# Implementasi Enkripsi dan Dekripsi Teks Menggunakan AES-128 CBC
# Program Studi Teknik Informatika - Universitas Maritim Raja Ali Haji
# Dibuat oleh: Christian Aprilio Sihite, Andrian Yuza Swanda,
#              Muhammad Fauzi, Adhie Mulia Sembiring
# ============================================================
# Referensi: NIST FIPS PUB 197 - Advanced Encryption Standard (AES)
# Implementasi manual TANPA library AES (sesuai proposal)
# ============================================================

import os
import base64
import gradio as gr

# ─────────────────────────────────────────────────────────────
# S-BOX dan INV_SBOX (NIST FIPS 197, Tabel 4 & 5)
# ─────────────────────────────────────────────────────────────
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

# ─────────────────────────────────────────────────────────────
# Galois Field GF(2^8) untuk MixColumns
# ─────────────────────────────────────────────────────────────
def gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

# ─────────────────────────────────────────────────────────────
# Key Expansion (NIST FIPS 197)
# ─────────────────────────────────────────────────────────────
def key_expansion(key: bytes) -> list:
    Nk = len(key) // 4
    Nr = Nk + 6
    w = [list(key[4*i : 4*i+4]) for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        temp = w[i-1][:]
        if i % Nk == 0:
            temp = [temp[1], temp[2], temp[3], temp[0]]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = [SBOX[b] for b in temp]
        w.append([w[i-Nk][j] ^ temp[j] for j in range(4)])
    return w

# ─────────────────────────────────────────────────────────────
# Empat Transformasi AES
# ─────────────────────────────────────────────────────────────
def add_round_key(state, rk, rd):
    for col in range(4):
        for row in range(4):
            state[row][col] ^= rk[rd*4 + col][row]

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]

def shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]

def inv_shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][4-r:] + state[r][:4-r]

def mix_columns(state):
    for c in range(4):
        v = [state[r][c] for r in range(4)]
        state[0][c] = gmul(2,v[0]) ^ gmul(3,v[1]) ^ v[2]         ^ v[3]
        state[1][c] = v[0]         ^ gmul(2,v[1]) ^ gmul(3,v[2])  ^ v[3]
        state[2][c] = v[0]         ^ v[1]          ^ gmul(2,v[2]) ^ gmul(3,v[3])
        state[3][c] = gmul(3,v[0]) ^ v[1]          ^ v[2]         ^ gmul(2,v[3])

def inv_mix_columns(state):
    for c in range(4):
        v = [state[r][c] for r in range(4)]
        state[0][c] = gmul(14,v[0])^gmul(11,v[1])^gmul(13,v[2])^gmul(9, v[3])
        state[1][c] = gmul(9, v[0])^gmul(14,v[1])^gmul(11,v[2])^gmul(13,v[3])
        state[2][c] = gmul(13,v[0])^gmul(9, v[1])^gmul(14,v[2])^gmul(11,v[3])
        state[3][c] = gmul(11,v[0])^gmul(13,v[1])^gmul(9, v[2])^gmul(14,v[3])

# ─────────────────────────────────────────────────────────────
# Enkripsi / Dekripsi Satu Blok 128-bit
# ─────────────────────────────────────────────────────────────
def encrypt_block(block: bytes, rk: list, Nr: int) -> bytes:
    state = [[block[r + 4*c] for c in range(4)] for r in range(4)]
    add_round_key(state, rk, 0)
    for rd in range(1, Nr):
        sub_bytes(state); shift_rows(state); mix_columns(state); add_round_key(state, rk, rd)
    sub_bytes(state); shift_rows(state); add_round_key(state, rk, Nr)
    return bytes(state[r][c] for c in range(4) for r in range(4))

def decrypt_block(block: bytes, rk: list, Nr: int) -> bytes:
    state = [[block[r + 4*c] for c in range(4)] for r in range(4)]
    add_round_key(state, rk, Nr)
    inv_shift_rows(state); inv_sub_bytes(state)
    for rd in range(Nr-1, 0, -1):
        add_round_key(state, rk, rd); inv_mix_columns(state); inv_shift_rows(state); inv_sub_bytes(state)
    add_round_key(state, rk, 0)
    return bytes(state[r][c] for c in range(4) for r in range(4))

# ─────────────────────────────────────────────────────────────
# Padding PKCS#7
# ─────────────────────────────────────────────────────────────
def pkcs7_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Data kosong setelah dekripsi.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding PKCS#7 tidak valid.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 rusak — kemungkinan kunci salah.")
    return data[:-pad_len]

# ─────────────────────────────────────────────────────────────
# Mode CBC
# ─────────────────────────────────────────────────────────────
def aes_cbc_encrypt(plaintext: bytes, key: bytes) -> tuple:
    Nr = len(key) // 4 + 6
    rk = key_expansion(key)
    padded = pkcs7_pad(plaintext)
    iv = os.urandom(16)
    prev = iv
    ct_blocks = []
    for i in range(0, len(padded), 16):
        blk   = padded[i:i+16]
        xored = bytes(b ^ p for b, p in zip(blk, prev))
        enc   = encrypt_block(xored, rk, Nr)
        ct_blocks.append(enc)
        prev  = enc
    full_ct = iv + b''.join(ct_blocks)
    ct_b64  = base64.b64encode(full_ct).decode()
    info = (
        f"✅ Enkripsi Berhasil!\n"
        f"{'━'*38}\n"
        f"  Algoritma   : AES-{len(key)*8}-CBC\n"
        f"  Panjang Key : {len(key)} byte ({len(key)*8} bit)\n"
        f"  Jumlah Round: {Nr}\n"
        f"  Plaintext   : {len(plaintext)} byte\n"
        f"  Setelah Pad : {len(padded)} byte\n"
        f"  IV (hex)    : {iv.hex()}\n"
        f"  Ciphertext  : {len(full_ct)} byte (IV + data)\n"
        f"{'━'*38}\n"
        f"  Proses CBC:\n"
        f"  1. Padding PKCS#7 ditambahkan\n"
        f"  2. IV 16 byte dibangkitkan secara acak\n"
        f"  3. Key Expansion → {(Nr+1)*4} round keys\n"
        f"  4. AddRoundKey awal (Round 0)\n"
        f"  5. {Nr-1}x Loop: SubBytes→ShiftRows→MixColumns→AddRoundKey\n"
        f"  6. Final Round (ke-{Nr}): SubBytes→ShiftRows→AddRoundKey\n"
        f"     (MixColumns dilewati sesuai NIST FIPS 197)\n"
        f"  7. Output dikonversi ke Base64\n"
    )
    return ct_b64, iv.hex(), info

def aes_cbc_decrypt(ct_b64: str, key: bytes) -> tuple:
    try:
        full_ct = base64.b64decode(ct_b64)
    except Exception:
        raise ValueError("Format Base64 tidak valid. Pastikan ciphertext tidak diubah.")
    if len(full_ct) < 32:
        raise ValueError("Ciphertext terlalu pendek (minimal 32 byte: 16 IV + 16 data).")
    if (len(full_ct) - 16) % 16 != 0:
        raise ValueError("Panjang ciphertext tidak valid (harus kelipatan 16 byte setelah IV).")
    Nr = len(key) // 4 + 6
    rk = key_expansion(key)
    iv, ct = full_ct[:16], full_ct[16:]
    prev = iv
    pt_blocks = []
    for i in range(0, len(ct), 16):
        blk = ct[i:i+16]
        dec = decrypt_block(list(blk), rk, Nr)
        pt_blocks.append(bytes(b ^ p for b, p in zip(dec, prev)))
        prev = blk
    plaintext = pkcs7_unpad(b''.join(pt_blocks))
    try:
        result = plaintext.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Hasil dekripsi bukan teks UTF-8 yang valid. Kemungkinan kunci salah.")
    info = (
        f"✅ Dekripsi Berhasil!\n"
        f"{'━'*38}\n"
        f"  Algoritma   : AES-{len(key)*8}-CBC\n"
        f"  Panjang Key : {len(key)} byte ({len(key)*8} bit)\n"
        f"  Jumlah Round: {Nr}\n"
        f"  IV (hex)    : {iv.hex()}\n"
        f"  Ciphertext  : {len(ct)} byte\n"
        f"  Plaintext   : {len(plaintext)} byte\n"
        f"{'━'*38}\n"
        f"  Proses Dekripsi CBC:\n"
        f"  1. Base64 dikonversi ke binary\n"
        f"  2. IV dipisahkan (16 byte pertama)\n"
        f"  3. Key Expansion → {(Nr+1)*4} round keys\n"
        f"  4. Final Round Invers: InvShiftRows→InvSubBytes→AddRoundKey\n"
        f"  5. {Nr-1}x Loop Invers: AddRoundKey→InvMixColumns→InvShiftRows→InvSubBytes\n"
        f"  6. AddRoundKey awal (Round 0)\n"
        f"  7. Padding PKCS#7 dihapus\n"
    )
    return result, info

# ─────────────────────────────────────────────────────────────
# Handler Gradio
# ─────────────────────────────────────────────────────────────
def gradio_encrypt(plaintext: str, key_str: str):
    if not plaintext.strip():
        return "", "❌ Error: Plaintext tidak boleh kosong.", ""
    if not key_str:
        return "", "❌ Error: Kunci tidak boleh kosong.", ""
    key_bytes = key_str.encode('utf-8')
    if len(key_bytes) != 16:
        return (
            "",
            f"❌ Error: Panjang kunci harus tepat 16 karakter.\n"
            f"   Sekarang: {len(key_bytes)} karakter.\n"
            f"   Sesuai proposal, project ini menggunakan AES-128 (kunci 128-bit = 16 byte).",
            ""
        )
    try:
        ct_b64, iv_hex, info = aes_cbc_encrypt(plaintext.encode('utf-8'), key_bytes)
        return ct_b64, info, iv_hex
    except Exception as e:
        return "", f"❌ Error tidak terduga: {str(e)}", ""

def gradio_decrypt(ct_b64: str, key_str: str):
    if not ct_b64.strip():
        return "", "❌ Error: Ciphertext tidak boleh kosong."
    if not key_str:
        return "", "❌ Error: Kunci tidak boleh kosong."
    key_bytes = key_str.encode('utf-8')
    if len(key_bytes) != 16:
        return (
            "",
            f"❌ Error: Panjang kunci harus tepat 16 karakter (sekarang: {len(key_bytes)} karakter)."
        )
    try:
        result, info = aes_cbc_decrypt(ct_b64.strip(), key_bytes)
        return result, info
    except Exception as e:
        return "", f"❌ Dekripsi Gagal: {str(e)}"

def update_key_info(key_str: str, mode: str) -> str:
    n = len(key_str.encode('utf-8'))
    ok = "✅" if n == 16 else "❌"
    return f"{ok} Panjang kunci: **{n} / 16 karakter**"

# ─────────────────────────────────────────────────────────────
# Antarmuka Gradio (kompatibel Gradio 6.x)
# ─────────────────────────────────────────────────────────────
css = """
.gr-button-primary { background: #2563eb !important; }
.header-html { text-align:center; padding:16px; background:linear-gradient(135deg,#1e3a5f,#2563eb);
               border-radius:12px; margin-bottom:8px; color:white; }
.info-html   { background:#f0f7ff; border-left:4px solid #2563eb; padding:12px;
               border-radius:6px; font-size:13px; margin-bottom:4px; }
footer { display:none !important; }
"""

with gr.Blocks(title="Sistem Enkripsi AES-128 CBC") as demo:

    gr.HTML("""
    <div class="header-html">
        <h2 style="margin:0;font-size:1.5rem;">🔐 Sistem Enkripsi &amp; Dekripsi AES-128 CBC</h2>
        <p style="margin:6px 0 0;opacity:0.85;font-size:0.9rem;">
            Implementasi Manual Tanpa Library AES &nbsp;·&nbsp; NIST FIPS PUB 197<br>
            Teknik Informatika &nbsp;·&nbsp; Universitas Maritim Raja Ali Haji &nbsp;·&nbsp; 2026
        </p>
    </div>
    <div class="info-html">
        <b>ℹ️ Cara Penggunaan:</b><br>
        &bull; <b>Enkripsi:</b> Isi teks pesan + kunci rahasia (tepat 16 karakter), klik <b>Enkripsi</b>.<br>
        &bull; <b>Dekripsi:</b> Tempelkan hasil ciphertext (Base64) + kunci yang <b>sama</b>, klik <b>Dekripsi</b>.<br>
        &bull; IV disimpan otomatis di dalam ciphertext — tidak perlu diinput terpisah.
    </div>
    """)

    with gr.Tabs():

        # ── TAB ENKRIPSI ──
        with gr.TabItem("🔒 Enkripsi"):
            gr.Markdown("### Input")
            with gr.Row():
                with gr.Column():
                    enc_plaintext = gr.Textbox(
                        label="Teks Pesan (Plaintext)",
                        placeholder="Masukkan pesan yang ingin dienkripsi...",
                        lines=5
                    )
                    enc_key = gr.Textbox(
                        label="Kunci Rahasia AES-128 (tepat 16 karakter)",
                        placeholder="Contoh: MySecretKey12345",
                        max_lines=1
                    )
                    enc_key_info = gr.Markdown("❌ Panjang kunci: **0 / 16 karakter**")
                    with gr.Row():
                        btn_encrypt   = gr.Button("🔒 Enkripsi",   variant="primary")
                        btn_enc_clear = gr.Button("🗑️ Bersihkan")

                with gr.Column():
                    enc_output = gr.Textbox(
                        label="Hasil Ciphertext (Base64) — Salin untuk Dekripsi",
                        lines=5, interactive=False
                    )
                    enc_iv = gr.Textbox(
                        label="IV yang Digunakan (Hex) — hanya informasi",
                        max_lines=1, interactive=False
                    )
                    enc_info = gr.Textbox(
                        label="📋 Log Proses AES",
                        lines=12, interactive=False
                    )

            enc_key.change(
                fn=lambda k: update_key_info(k, "enc"),
                inputs=enc_key, outputs=enc_key_info
            )
            btn_encrypt.click(
                fn=gradio_encrypt,
                inputs=[enc_plaintext, enc_key],
                outputs=[enc_output, enc_info, enc_iv]
            )
            btn_enc_clear.click(
                fn=lambda: ("", "", "", "❌ Panjang kunci: **0 / 16 karakter**", ""),
                outputs=[enc_plaintext, enc_key, enc_output, enc_key_info, enc_iv]
            )

        # ── TAB DEKRIPSI ──
        with gr.TabItem("🔓 Dekripsi"):
            gr.Markdown("### Input")
            with gr.Row():
                with gr.Column():
                    dec_ciphertext = gr.Textbox(
                        label="Ciphertext (Base64)",
                        placeholder="Tempelkan hasil enkripsi (Base64) di sini...",
                        lines=5
                    )
                    dec_key = gr.Textbox(
                        label="Kunci Rahasia (harus sama dengan saat enkripsi)",
                        placeholder="Masukkan kunci yang sama (16 karakter)...",
                        max_lines=1
                    )
                    dec_key_info = gr.Markdown("❌ Panjang kunci: **0 / 16 karakter**")
                    with gr.Row():
                        btn_decrypt   = gr.Button("🔓 Dekripsi",   variant="primary")
                        btn_dec_clear = gr.Button("🗑️ Bersihkan")

                with gr.Column():
                    dec_output = gr.Textbox(
                        label="Hasil Plaintext",
                        lines=6, interactive=False
                    )
                    dec_info = gr.Textbox(
                        label="📋 Log Proses AES",
                        lines=12, interactive=False
                    )

            dec_key.change(
                fn=lambda k: update_key_info(k, "dec"),
                inputs=dec_key, outputs=dec_key_info
            )
            btn_decrypt.click(
                fn=gradio_decrypt,
                inputs=[dec_ciphertext, dec_key],
                outputs=[dec_output, dec_info]
            )
            btn_dec_clear.click(
                fn=lambda: ("", "", "", "❌ Panjang kunci: **0 / 16 karakter**"),
                outputs=[dec_ciphertext, dec_key, dec_output, dec_key_info]
            )

        # ── TAB TENTANG ──
        with gr.TabItem("📚 Tentang Algoritma"):
            gr.Markdown("""
## Implementasi AES-128 CBC — NIST FIPS PUB 197

### Apa itu AES?
**Advanced Encryption Standard (AES)** adalah algoritma enkripsi simetris berbasis *block cipher*
yang ditetapkan NIST sebagai standar global. Project ini menggunakan **AES-128** —
kunci **128-bit (16 byte)** dengan **10 putaran enkripsi**.

---

### Empat Transformasi Inti AES

| Transformasi | Fungsi |
|---|---|
| **SubBytes** | Substitusi non-linear byte via S-Box → *Confusion* |
| **ShiftRows** | Pergeseran baris state secara siklis → *Diffusion* |
| **MixColumns** | Perkalian matriks dalam GF(2⁸) → *Diffusion antar kolom* |
| **AddRoundKey** | XOR state dengan round key |

---

### Mode CBC (Cipher Block Chaining)
```
Enkripsi: C_i = AES_Encrypt(P_i XOR C_{i-1}),  C_0 = IV (acak)
Dekripsi: P_i = AES_Decrypt(C_i) XOR C_{i-1},  C_0 = IV
```
IV disimpan otomatis di 16 byte pertama ciphertext.

---

### Padding PKCS#7
Karena AES memproses blok 16 byte, plaintext dilengkapi padding:
- Kurang N byte → tambah N byte bernilai `N`
- Contoh: plaintext 13 byte → tambah `03 03 03`

---

### Implementasi Mandiri
Program ini **tidak menggunakan library AES** (`pycryptodome`, `cryptography`, dsb).
Seluruh algoritma — S-Box, Key Expansion, gmul GF(2⁸), semua transformasi —
diimplementasikan secara **manual** sesuai proposal dan NIST FIPS PUB 197.

---
*Kelompok AES · Kelas C · Teknik Informatika UMRAH · 2026*
            """)

# ─────────────────────────────────────────────────────────────
# Jalankan Aplikasi
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  Sistem Enkripsi AES-128 CBC")
    print("  Teknik Informatika - UMRAH 2026")
    print("=" * 50)
    print("  Membuka di: http://localhost:7860")
    print("  Tekan Ctrl+C untuk menghentikan.")
    print("=" * 50)
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        inbrowser=True
    )