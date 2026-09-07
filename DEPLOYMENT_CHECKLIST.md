# CHECKLIST DEPLOY PRODUKSI

1. Buat `.env` dari `.env.example`.
2. Ganti JWT_SECRET dengan random string panjang.
3. Ganti ADMIN_PASSWORD.
4. Ganti password database pada docker-compose.yml dan DATABASE_URL.
5. Pastikan port PostgreSQL tidak diekspos ke publik.
6. Jalankan `docker compose up -d --build`.
7. Pasang reverse proxy HTTPS (Nginx/Caddy).
8. Arahkan domain/subdomain ke server.
9. Login sebagai admin dan buat akun Kepala KPLP/operator.
10. Uji akses sesuai role.
11. Uji backup PostgreSQL.
12. Dokumentasikan SOP penggunaan dan pengelolaan akun.
13. Lakukan UAT sebelum dipakai operasional.
