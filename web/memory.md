# memory.md — web/

Frontend React + TypeScript + Vite. Dashboard pentru vizualizarea scanarilor,
management dispozitive, scan-on-demand din UI.

## Stack

- **React 19** + React Router 7
- **TypeScript 5.9**
- **Vite 7** (HMR, proxy `/api/*` la backend in dev)
- **Vitest 4** + **@testing-library/react** + **jsdom** pentru teste unitare componente
- **ESLint** + `eslint-plugin-react-hooks` + `eslint-plugin-react-refresh`

Sesiune autentificata prin **cookie HttpOnly** setat de backend la
`/auth/login`. Frontend-ul nu citeste / nu stocheaza tokenul — `credentials:
"include"` in fetch face browser-ul sa-l trimita automat.

## Continut

| Fisier / folder         | Rol                                                                  |
| ----------------------- | -------------------------------------------------------------------- |
| `src/`                  | Cod sursa React. Vezi `src/memory.md`.                               |
| `public/`               | Asset-uri statice servite as-is. Vezi `public/memory.md`.            |
| `index.html`            | Template HTML — punctul de intrare Vite. `<div id="root">`.          |
| `package.json`          | Dependencies + scripts: `dev` (Vite dev server), `build` (`tsc -b && vite build`), `lint`, `preview`, **`test` (vitest run)**, **`test:watch`**. |
| `package-lock.json`     | Lock file npm — versiuni exacte ale tuturor tranzitivelor.           |
| `vite.config.ts`        | Plugin `@vitejs/plugin-react`; proxy `server: { proxy: { "/api": { target: "http://127.0.0.1:8000" } } }`. **Code-splitting (2026-06-11):** `build.rollupOptions.output.manualChunks` separa `react` (react+react-dom+react-router-dom), `recharts` si `motion` (framer-motion) in chunk-uri proprii — bundle-ul principal a scazut de la ~812 KB la ~260 KB. |
| `tsconfig.json`         | Root config — referinta la `tsconfig.app.json` si `tsconfig.node.json`. |
| `tsconfig.app.json`     | Config TS pentru codul aplicatiei (`src/**`). Strict, target modern. |
| `tsconfig.node.json`    | Config TS pentru `vite.config.ts` si scripturi de build (Node-side). |
| `eslint.config.js`      | Flat ESLint config v9; reguli React Hooks + React Refresh.           |
| `.env`                  | `VITE_API_BASE_URL=/api/v1`. Dev only; productie ar suprascrie cu URL absolut. |
| `.gitignore`            | Exclude `node_modules`, `dist`, `dist-ssr`, log-uri.                 |
| `README.md`             | Documentatie pentru frontend: stack, rulare, layout, structura API client. |

## Rulare

```powershell
cd web
npm install
npm run dev
```

UI disponibil la `http://localhost:5173`. Vite proxy-eaza `/api/*` la
`http://127.0.0.1:8000` — astfel cookie-ul de pe `localhost:5173` ajunge
la backend ca si cum ar fi pe acelasi origin.

## Build pentru productie

```powershell
npm run build      # → dist/
npm run preview    # serveste dist/ pe :4173 pentru smoke test
```

In productie, backend-ul ar trebui sa serveasca `dist/` ca static
(sau un nginx in fata) si CORS sa fie strict pe domeniul de productie.

## API client

Toata comunicarea HTTP trece prin `src/api/http.ts`. Vezi `src/api/memory.md`.

## Teste

```powershell
npm test          # ruleaza o data si iese (ideal pentru CI)
npm run test:watch # watch mode
```

Setup-ul vitest e in `vite.config.ts` cu `test.environment: "jsdom"` si
`setupFiles: ["./src/test/setup.ts"]` (importa matchers de la
@testing-library/jest-dom). Conventie: fisierele de test sunt langa
componenta lor, cu suffix `.test.tsx`.

Acoperire actuala: `ScoreBreakdownBars`, `ScoreGauge`, `UserAvatar` (18 teste).
Pattern-ul demonstrat → user-ul poate adauga teste similare pentru `ScanDiff`,
`ScoreTrendChart`, paginile principale.
