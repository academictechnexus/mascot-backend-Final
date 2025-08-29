# Mascot Backend (Railway-ready)

## Endpoints
- `GET /`              -> "OK" (for Railway/root health)
- `GET /health`        -> `{ ok: true, ... }`
- `GET /openai/ping`   -> checks your API key with OpenAI
- `POST /chat`         -> `{ reply: "..." }` (body: `{ "message": "..." }`)
- `POST /mascot/upload`-> `{ success, url }` (multipart/form-data field: `mascot`)

## Deploy to Railway
1. Create a **new GitHub repo** with these files.
2. On Railway → New Project → Deploy from GitHub → choose your repo.
3. In Railway → **Variables**, add:
   - `OPENAI_API_KEY = sk-xxxxxxxx`
   - (optional) `RATE_LIMIT_WINDOW_MS = 10000`
   - (optional) `RATE_LIMIT_MAX = 8`
4. In Service → **Settings → Health Check Path**, set `/health`.
5. (Optional) add a custom domain and point DNS to Railway's provided target.

## Test
```bash
curl https://<your-domain>/health
curl https://<your-domain>/openai/ping

curl -X POST https://<your-domain>/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"Say hi in one line"}'

curl -X POST https://<your-domain}/mascot/upload \
  -F "mascot=@./my.png"
```

## Frontend usage
```js
const API_BASE = "https://<your-domain>";
const res = await fetch(`${API_BASE}/chat`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ message: "Hello" })
});
const data = await res.json(); // { reply: "..." }
```

### Upload
```js
const form = new FormData();
form.append("mascot", file);
const up = await fetch(`${API_BASE}/mascot/upload`, { method: "POST", body: form });
const out = await up.json(); // { success: true, url: "..." }
```
