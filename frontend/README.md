# Quiver Frontend

SPA UI for Quiver.

Implemented routes:

- `/dashboard`: live operational metrics.
- `/history`: historical metric visualization.
- `/flows`: flow explorer and record detail.
- `/analytics`: protocol, port, and talker aggregates.
- `/logs`: backend log viewer.

The app uses same-origin API calls by default. API base URL and API key overrides are stored in browser `localStorage` and sent only through `X-API-Key`.

## Scripts

```bash
npm run dev
npm run typecheck
npm run lint
npm run format:check
npm run test
npm run build
npm run preview
```

`npm run build` writes `dist/`. The repository-level `make frontend-build`
copies that output into `internal/web/dist`, which is embedded into the Go
binary and served with SPA fallback routing.
