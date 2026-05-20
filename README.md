# BackendOnly (Dompetku API Proxy)

Folder ini backend terpisah untuk dipasang di VPS Ubuntu tanpa upload seluruh project frontend.

Arsitektur:

`Capacitor / APK / Frontend` -> `BackendOnly (VPS)` -> `OpenRouter API`

## 1) Upload ke VPS

Upload folder `BackendOnly` saja ke VPS, misalnya:

`/var/www/BackendOnly`

## 2) Install dependency

```bash
cd /var/www/BackendOnly
npm install
```

## 3) Setup env

```bash
cp .env.example .env
nano .env
```

Wajib isi:

- `OPENROUTER_API_KEY` (valid)
- `OPENROUTER_MODEL_FREE=deepseek/deepseek-v4-flash:free`
- `OPENROUTER_MODEL_REPORT_RECOMMENDATION=deepseek/deepseek-v4-flash:free`
- `CORS_ALLOWED_ORIGINS` (domain frontend kamu + origin Capacitor: `http://localhost`, `https://localhost`, `capacitor://localhost`)

Contoh:

```env
NODE_ENV=production
PORT=3000
OPENROUTER_API_KEY=sk-or-v1-xxxx
OPENROUTER_MODEL_FREE=deepseek/deepseek-v4-flash:free
OPENROUTER_MODEL_REPORT_RECOMMENDATION=deepseek/deepseek-v4-flash:free
OPENROUTER_MODEL_QUICK_SUGGEST=deepseek/deepseek-v4-flash:free
CORS_ALLOWED_ORIGINS=http://localhost,https://localhost,http://localhost:3000,https://localhost:3000,capacitor://localhost,https://app.domainkamu.com
```

## 4) Jalankan dengan PM2

### Opsi cepat

```bash
pm2 start server.js --name Dompetku-BackendOnly
pm2 save
```

### Opsi pakai ecosystem

Edit `cwd` di `ecosystem.config.cjs` jika beda path, lalu:

```bash
pm2 start ecosystem.config.cjs
pm2 save
```

## 5) Cek status dan log

```bash
pm2 list
pm2 logs Dompetku-BackendOnly --lines 100
```

## Endpoint yang tersedia

- `GET /health`
- `GET /api/health/ai`
- `POST /api/chat`
- `POST /api/chat/stream` (SSE, kompatibel dengan frontend sekarang)
- `POST /api/quick-suggestions`
- `POST /api/report/recommendations`
- `POST /api/iap/google/verify`

## Contoh test dari VPS

```bash
curl -sS http://127.0.0.1:3000/health
```

```bash
curl -sS -X POST http://127.0.0.1:3000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt":"catat makan 20 ribu","currentData":{"income":{},"expenses":{},"savings":{},"debts":{},"assets":{},"budgets":{},"goals":{},"transactions":[]},"language":"Indonesian"}'
```

## Catatan keamanan

- Jangan expose `OPENROUTER_API_KEY` di frontend / APK.
- Jika key pernah bocor, segera revoke/rotate key di OpenRouter.
- Batasi `CORS_ALLOWED_ORIGINS` hanya domain/app yang kamu pakai.
