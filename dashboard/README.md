# Sentinel Dashboard

A Next.js + Tailwind dashboard that visualises a Sentinel `report.json`: severity summary,
per-severity filtering, and a card per finding with its remediation.

## Run locally

```bash
cd dashboard
npm install
npm run dev
```

Open http://localhost:3000.

## Loading your own data

The dashboard reads `public/report.json`. Generate a real one from the toolkit and copy it in:

```bash
# from the repo root
sentinel scan-all --format json --output-dir reports
cp reports/report-*.json dashboard/public/report.json
```

A representative sample report ships in `public/report.json` so the dashboard renders out of the box.
