# memory.md — web/src/assets/

Asset-uri importate in cod si procesate de Vite (hashing, code-splitting,
tree-shaking). Pentru asset-uri servite as-is, vezi `web/public/`.

## Continut

| Fisier        | Rol                                                                  |
| ------------- | -------------------------------------------------------------------- |
| `react.svg`   | Logo React (din template-ul Vite). Inca nu este folosit in cod activ — VulnWatch foloseste icon-uri SVG inline (vezi `ShieldIcon` in `pages/Login.tsx`, `pages/Register.tsx`, `components/Navbar.tsx`). |

## De ce SVG inline pentru icon-uri?

Componentele de pe paginile principale (Navbar, Login, Devices, Dashboard)
declara mici componente SVG ca `ShieldIcon`, `SearchIcon`, `CopyIcon` direct
in TSX. Avantaje:
- Zero import overhead — SVG-ul e parte din bundle, dar inline.
- Stiluri (stroke, fill) controlabile via props si CSS variables.
- Tema dynamic (currentColor) functioneaza fara munca extra.

`react.svg` ramane aici ca leftover din scaffolding; il poti sterge cand
faci cleanup.
