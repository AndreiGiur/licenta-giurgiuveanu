# VulnWatch — Frontend

Dashboard React + TypeScript pentru platforma VulnWatch.

## Stack

- React 19 + React Router 7
- TypeScript 5.9
- Vite 7
- Sesiuni autentificate prin cookie HttpOnly (frontend-ul nu citește/stochează tokenul).

## Rulare

```bash
npm install
npm run dev
```

Disponibil pe `http://localhost:5173`. Vite proxy-ează `/api/*` la
`http://127.0.0.1:8000` (vezi `vite.config.ts`).

## Build pentru producție

```bash
npm run build
npm run preview     # opțional, servește dist/
```

## Pagini

| Rută                | Descriere                                              | Acces        |
| ------------------- | ------------------------------------------------------ | ------------ |
| `/login`            | Autentificare                                          | public       |
| `/register`         | Înregistrare cont nou                                  | public       |
| `/dashboard`        | Listează scanări per device, afișează findings         | protejat     |
| `/devices`          | Înrolare/listare/ștergere dispozitive                  | protejat     |
| `/scans/:scanId`    | Detalii scanare (findings, evidence, payload sistem)   | protejat     |

`ProtectedRoute` validează sesiunea contactând `GET /auth/me`. Cookie-ul
HttpOnly se trimite automat (browser-ul îl gestionează — niciun cod JS nu îl
citește, ceea ce blochează atacurile XSS din rădăcină).

## Configurare

`web/.env`:

```env
VITE_API_BASE_URL=/api/v1
```

În dev, calea relativă funcționează cu proxy-ul Vite. Pentru producție,
setează URL-ul absolut al backend-ului dacă frontend-ul e servit de pe alt
domeniu (atenție la CORS și `COOKIE_SAMESITE` în backend).

## Structură API client

Toată logica HTTP trăiește în `src/api/http.ts`:

- `apiGet<T>(path)`, `apiPost<TReq, TRes>(path, body)`, `apiDelete<T>(path)`
- toate fac `credentials: "include"` (cookie-ul de sesiune)
- timeout default 8s, parser JSON cu `HttpError` care expune `status` + `body`

`src/api/auth.ts` expune `loginUser`, `registerUser`, `fetchMe`, `logoutUser`
pentru pagini și componente.
