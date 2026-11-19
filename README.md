# Am I Affected?

Paste a lockfile and see which known vulnerabilities hit your dependencies, plus this week's headline bugs.

- Runs entirely in the browser: the lockfile is parsed client-side, and only package names + versions are sent to [OSV.dev](https://osv.dev).
- Supported: package-lock.json, yarn.lock (v1 + berry), pnpm-lock.yaml, Gemfile.lock, poetry.lock, uv.lock, Pipfile.lock, pinned requirements.txt, Cargo.lock, go.sum / go.mod, composer.lock.
- "New critical vulnerabilities" (`docs/recent.json`) is rebuilt daily by a GitHub Action (`build_recent.py`) from OSV's public bucket: critical advisories published in the last 14 days, flagged if CISA lists them as actively exploited. Matching packages are pinned to the top of results. No manual upkeep.

Static site (GitHub Pages, `docs/`). Parser tests: `cd test && node run.mjs`.
