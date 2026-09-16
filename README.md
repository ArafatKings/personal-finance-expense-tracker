# PFTracker — Personal Finance Expense Tracker

A complete university-ready full-stack implementation based on the supplied Personal Finance Expense Tracker proposal, using a modern local stack:

- React + Vite frontend
- Node.js + Express REST API
- SQLite database engine through `sql.js` (WASM, so no Visual Studio/C++ build tools, MySQL, XAMPP or Apache are required)
- Chart.js data visualization
- Bootstrap 5 + custom responsive CSS
- bcryptjs password hashing
- express-session authentication

## Proposal coverage

The application implements the proposal's core requirements: registration/login/logout, session-based access control, dashboard totals, recent transactions, category spending charts, income/expense CRUD, categories, search and filters, automatic balance calculation, monthly summaries, visual reports, and responsive layouts.

## Run locally

Requirements: Node.js 20+ recommended.

```bash
npm install
npm run dev
```

Open http://localhost:5173

The API runs at http://localhost:3000.

## Demo account

Email: `demo@pftracker.local`
Password: `Demo@12345`

You can also register your own account.

## Database

The local database is created automatically at:

`data/finance.sqlite`

The database is a real SQLite database file. `sql.js` runs SQLite through WebAssembly, avoiding native compiler setup on Windows.

## Main sections

Dashboard · Transactions · Income · Expenses · Categories · Reports & Analytics · Monthly Summary · Settings

## Production note

This is intended as a local university project/demo. For production deployment, replace the in-memory Express session store with a persistent session store, use environment variables for secrets, add CSRF protection, HTTPS, rate limiting, and additional validation.


## Netlify deployment

This repository contains the original local version plus a Netlify Function for the online API. The online API uses a persistent Turso/libSQL database and signed HttpOnly authentication cookies.

### Netlify settings
- Build command: `npm run build`
- Publish directory: `dist`
- Functions directory: `netlify/functions`

### Required Netlify environment variables
- `TURSO_DATABASE_URL` — your Turso database URL
- `TURSO_AUTH_TOKEN` — your Turso database auth token
- `PFTRACKER_JWT_SECRET` — a long random secret used to sign login cookies

Do not put these secrets in GitHub. Add them in Netlify Project configuration → Environment variables.

### Important
The `data/finance.sqlite` file is for local development. Netlify uses the Turso database when the site is deployed.
