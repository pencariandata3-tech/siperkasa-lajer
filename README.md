# SIPERKASA LAJER ONLINE — Multi User & Multi Device

Versi ini adalah aplikasi web full-stack yang dapat dipasang di server/internet/intranet dan digunakan bersama dari laptop, PC, tablet, atau ponsel melalui browser.

## Fitur
- Login multi-user
- Role-based access:
  - `admin`
  - `kepala_kplp`
  - `operator`
- Dashboard overcrowding
- Data dan pemetaan risiko blok
- Penilaian risiko WBP
- Kontrol & deteksi dini
- Insiden kamtib
- Laporan dan ekspor CSV
- Audit log
- PostgreSQL terpusat
- Docker-ready
- Responsive untuk desktop dan mobile

## Data awal
- Kapasitas: 390
- Penghuni: 939

## Cara menjalankan paling mudah dengan Docker

1. Install Docker Desktop pada komputer/server.
2. Ekstrak ZIP aplikasi.
3. Salin `.env.example` menjadi `.env`.
4. WAJIB ubah:
   - `JWT_SECRET`
   - `ADMIN_PASSWORD`
   - bila perlu password PostgreSQL di `docker-compose.yml` dan `DATABASE_URL`
5. Jalankan:
   ```bash
   docker compose up -d --build
   ```
6. Buka:
   `http://IP-SERVER:3000`

Jika dipasang di VPS/domain, arahkan domain ke server dan gunakan reverse proxy HTTPS (Nginx/Caddy/Cloudflare).

## Login pertama
Username mengikuti `ADMIN_USERNAME` pada `.env` (default: admin).
Password mengikuti `ADMIN_PASSWORD` pada `.env`.
Ganti password bootstrap sebelum dipakai produksi.

## Deploy ke internet
Aplikasi dapat dideploy ke:
- VPS Linux + Docker
- Railway
- Render
- Fly.io
- server internal/intranet instansi

Gunakan PostgreSQL persisten. Jangan memakai filesystem container untuk database.

## Keamanan produksi yang disarankan
- HTTPS wajib.
- Gunakan password kuat dan unik.
- JWT_SECRET minimal 32–64 karakter acak.
- Batasi akses aplikasi jika datanya sensitif (VPN/intranet/allowlist IP).
- Backup PostgreSQL terjadwal.
- Terapkan SOP retensi data.
- Minimalkan data pribadi WBP yang disimpan.
- Lakukan penilaian keamanan TI sebelum sistem dipakai sebagai sistem resmi instansi.
- Jangan membuka PostgreSQL langsung ke internet.
- Gunakan akun database dengan hak minimum.
- Lakukan patch/update dependency secara berkala.

## Struktur
- `server.js` — API, auth, RBAC, audit
- `public/index.html` — antarmuka aplikasi
- `sql/schema.sql` — struktur PostgreSQL
- `Dockerfile`
- `docker-compose.yml`
- `.env.example`

## Catatan
Aplikasi ini merupakan MVP siap-deploy. Untuk penggunaan resmi skala instansi, sebaiknya dilakukan hardening keamanan, UAT, backup/recovery drill, dan penyesuaian dengan kebijakan TI serta perlindungan data instansi.
