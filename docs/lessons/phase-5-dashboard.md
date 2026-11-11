# Phase 5 Lesson Notes: A React + TypeScript Dashboard

## 1. Why these tools
- **TypeScript** checks types before the code runs. `src/api/types.ts` mirrors the FastAPI response models, so if the backend renames a field, `npm run typecheck` points at every screen that breaks.
- **React** builds the UI from small functions (components) that return markup from data. When data changes, React redraws only what changed.
- **Vite** is the dev server and bundler. In development it forwards `/api` to FastAPI (`vite.config.ts`), so the browser sees one origin and CORS never comes up.
- **TanStack Query** handles server data: loading/error/success states, caching, refetching. Hand-written `useEffect + fetch` code gets these wrong in subtle ways.

## 2. Layout of `frontend/src`
```
api/types.ts     shapes of API data (mirror of backend schemas)
api/client.ts    ONE place that calls fetch: adds the token, turns errors into ApiError
auth.tsx         sign-in state; signs out automatically on a 401
theme.ts         dark (default) or light, saved in localStorage
styles/tokens.css  every color lives here; components never hard-code colors
pages/, components/  screens and reusable pieces
```

## 3. Design decisions worth knowing
- **Design tokens:** both themes are the same CSS with different variable values. A new theme is a new block of variables, not new components.
- **Never color alone:** severity is a word on a pill; evidence outcomes use a shape (dot, diamond), color and text. About 1 in 12 men have some color-vision difference.
- **Every state is designed:** loading, error with retry, empty ("no alerts match"), and "no data yet" for time-to-acknowledge, which shows a dash and a hint instead of `0`.
- **Roles in the UI:** viewers don't see write buttons. This is convenience only; the **API enforces roles**, and a test of the API (Phase 2) proves it. Never rely on hidden buttons for security.

## 4. Security tradeoffs
- The sign-in token is in `sessionStorage`: it survives reload, dies with the tab, but JavaScript can read it, so an XSS bug could steal it. React escapes text by default, and we never use `dangerouslySetInnerHTML`. The stronger fix is an httpOnly cookie (Phase 7).
- Log text (usernames, reasons) is rendered as plain text, never HTML. This matters because attackers write logs.
- Backend CORS is an explicit allow-list set by `CORS_ORIGINS`, off by default, never `*`.

## 5. Testing
`src/App.test.tsx` renders the real app against a fake `fetch` (`test/render.tsx`) and checks what a user sees: the sign-in redirect, error messages, empty states, viewer vs analyst buttons, and that clicking Acknowledge sends `PATCH {status: "acknowledged"}`. Test behavior, not implementation details.

## 6. Known limitations
- No alerts-over-time chart: the API has no time-series endpoint yet (adding `GET /alerts/timeline` is a good exercise).
- Events, Investigations and Model health pages are placeholders in the nav.
- Tested against a fake API and screenshots, not yet against a live browser session with the real backend.

## Exercises
1. Add a `source_ip` search box using the existing `source_ip` filter on `GET /alerts`.
2. Add the `GET /alerts/timeline` endpoint (GROUP BY hour) and draw it as an SVG area chart.
3. Write a test that a 401 from the API sends the user back to the sign-in page.
4. Why does `retry` in `main.tsx` skip 4xx errors?
