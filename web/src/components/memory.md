# memory.md — web/src/components/

Componente reutilizabile, folosite de mai multe pagini.

## Fisiere

| Fisier               | Rol                                                                  |
| -------------------- | -------------------------------------------------------------------- |
| `Navbar.tsx`         | Bara de sus prezenta in toate paginile protejate. Brand cu mark colorat + nume "VulnWatch" in font display (Fraunces). Link-uri: **Dashboard** + **Dispozitive** (cu evidentiere prin clasa `.active` in functie de `useLocation().pathname`, match exact sau prefix path). Pe dreapta: `<ThemeToggle>` (sun/moon) + `<UserAvatar>` (poza Google daca exista, altfel initiala) + buton **Logout**. La logout: apel `logoutUser()` urmat de redirect la `/login`. Daca request-ul esueaza, redirect-eaza oricum (defensiv). Refetch `me` la fiecare schimbare de pathname. |
| `ProtectedRoute.tsx` | **Gateway de auth** pentru rute protejate. Apeleaza `fetchMe()` in `useEffect` la mount. Daca returneaza 2xx → renderizeaza `children`. Daca esueaza → `navigate("/login", { replace: true })`. In timpul verificarii afiseaza `<div>Verificare sesiune...</div>` ca placeholder. Foloseste flag `cancelled` pentru cleanup la unmount (evita race condition). |
| `ThemeProvider.tsx`  | **Context React pentru tema light/dark.** Expune `<ThemeProvider>` + hook `useTheme()` cu `{ theme, toggle, setTheme }`. La initializare alege tema din `localStorage["vw-theme"]`, apoi fallback la `prefers-color-scheme: dark`, apoi `light`. Un `useEffect` seteaza `data-theme` pe `<html>` si persista alegerea in localStorage. CSS-ul din `index.css` reactioneaza la `[data-theme="dark"]` (paleta Plum & Honey). |
| `ThemeToggle.tsx`    | **Buton sun/moon** pentru toggle light/dark. Foloseste `useTheme()` + `motion.svg` (Framer Motion) cu animatie `rotate` la schimbare temei. Icon SVG inline: soare (light mode = afiseaza luna ca click target) / luna (dark mode = afiseaza soare). Stil prin `.theme-toggle` in `index.css` cu hover lift. |
| `GoogleButton.tsx`   | **Buton "Continua cu Google"** cu logo oficial G colorat (4 path-uri SVG). La click apeleaza `getGoogleAuthUrl()` (din `api/auth.ts`) si redirecteaza browserul la URL-ul Google OAuth. State loading = "Se redirecționează...". Prop-uri: `label`, `fullWidth`, `onError`. Folosit pe pagini Login si Register. |
| `UserAvatar.tsx`     | Mic avatar circular folosit in Navbar. Daca `pictureUrl` e setat (cont Google) afiseaza poza cu `referrerPolicy="no-referrer"`. Altfel afiseaza initiala emailului pe fundal `--accent`. Size configurabil (default 32px). |
| `ScoreGauge.tsx`     | **Inel SVG animat + numar tween** pentru afisarea exposure score. Foloseste Framer Motion (`useMotionValue` + `animate` + `useTransform`) — numarul cresc de la 0 la valoarea reala in 1.2s ease-out, inelul circular se umple sincronizat. Culoarea inelului = severitatea (`score-high` plum, `score-medium` honey, `score-low` lavanda, `score-none` sage). Size + strokeWidth + label configurabile. Stiluri prin `.score-gauge` in `index.css`. |
| `NmapHostCard.tsx`   | **Card per host descoperit de nmap** in deep scan. Afiseaza: IP + hostname + rol topologie (gateway/dns/fileserver/workstation), risc 0-100 din scriptul Lua, OS guess, lista porturi `open` (port/proto, service, version), lista `vulnwatch_findings` cu severity color-coded prin clase `.sev-{critical,high,medium,low,info}`. |
| `NmapSection.tsx`    | **Sectiune dedicata in ScanDetail** pentru output nmap. Header: `nmap {version}`, meta cu targets + scan_time_sec + numar hosts; lista de `<NmapHostCard>`-uri; `<details>` expandabil pentru `lua_errors`. Daca `nmap.error` (ex: `nmap_missing`, `no_output`), afiseaza un banner de eroare in loc de hosts. |

## Pattern de folosire

In `App.tsx`:

```tsx
<Route path="/dashboard" element={
  <ProtectedRoute>
    <Dashboard />
  </ProtectedRoute>
} />
```

`Navbar` este randat in interiorul fiecarei pagini protejate (nu la nivel
de `App.tsx`), pentru ca paginile de auth (Login, Register) nu vor sa-l aiba.
