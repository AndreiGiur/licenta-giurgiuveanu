# memory.md — web/src/components/

Componente reutilizabile, folosite de mai multe pagini.

## Fisiere

| Fisier               | Rol                                                                  |
| -------------------- | -------------------------------------------------------------------- |
| `Navbar.tsx`         | Bara de sus prezenta in toate paginile protejate. Brand cu icon scut + nume "VulnWatch". Link-uri: **Dashboard** + **Devices** (cu evidentiere prin clasa `.active` in functie de `useLocation().pathname`). Pe dreapta: badge cu email-ul user-ului (citit prin `fetchMe()` in `useEffect`) + buton **Logout**. La logout: apel `logoutUser()` (DELETE /auth/logout) urmat de redirect la `/login`. Daca request-ul esueaza, redirect-eaza oricum (defensiv). |
| `ProtectedRoute.tsx` | **Gateway de auth** pentru rute protejate. Apeleaza `fetchMe()` in `useEffect` la mount. Daca returneaza 2xx → renderizeaza `children`. Daca esueaza → `navigate("/login", { replace: true })`. In timpul verificarii afiseaza `<div>Verificare sesiune...</div>` ca placeholder. Foloseste flag `cancelled` pentru cleanup la unmount (evita race condition). |
| `ThemeProvider.tsx`  | **Context React pentru tema light/dark.** Expune `<ThemeProvider>` + hook `useTheme()` cu `{ theme, toggle, setTheme }`. La initializare alege tema din `localStorage["vw-theme"]`, apoi fallback la `prefers-color-scheme: dark`, apoi `light`. Un `useEffect` seteaza `data-theme` pe `<html>` si persista alegerea in localStorage. CSS-ul din `index.css` reactioneaza la `[data-theme="dark"]` (paleta Plum & Honey). |

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
