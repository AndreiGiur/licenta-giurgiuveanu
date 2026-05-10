# memory.md — web/public/

Asset-uri statice servite **as-is** de Vite, fara procesare. Calea publica
`/foo.svg` se mapeaza direct la `public/foo.svg`.

Pentru imagini importate in cod (cu transformari, hashing, code-splitting),
foloseste `src/assets/` in schimb.

## Continut

| Fisier        | Rol                                                                  |
| ------------- | -------------------------------------------------------------------- |
| `vite.svg`    | Logo Vite default (din template). Folosit ca favicon prin `<link rel="icon" href="/vite.svg">` in `index.html`. |

## Diferenta `public/` vs `src/assets/`

- **`public/`** — fisierul ramane neatins, calea e fixa (`/vite.svg`). Bun
  pentru favicon, robots.txt, sitemap, fisiere descarcabile cu nume stabile.
- **`src/assets/`** — fisierul e procesat de Vite, hash-uit pentru cache
  busting, importat ca modul. Bun pentru imagini folosite in JSX/CSS.
