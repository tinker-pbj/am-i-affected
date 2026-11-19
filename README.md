# Am I Affected?

Paste a lockfile and see which known vulnerabilities hit your dependencies, plus this week's headline bugs.

- Runs entirely in the browser: the lockfile is parsed client-side, and only package names + versions are sent to [OSV.dev](https://osv.dev).
- Supported: package-lock.json, yarn.lock (v1 + berry), pnpm-lock.yaml, bun.lock, deno.lock, Gemfile.lock, poetry.lock, uv.lock, pdm.lock, Pipfile.lock, pinned requirements.txt, Cargo.lock, go.sum / go.mod, composer.lock, pom.xml, gradle.lockfile, packages.lock.json, .csproj, pubspec.lock, mix.lock, Package.resolved, renv.lock, CycloneDX / SPDX SBOMs (JSON).
- "New critical vulnerabilities" (`docs/recent.json`) is rebuilt every 2 hours by a GitHub Action (`build_recent.py`) from OSV's public bucket: critical advisories published in the last 14 days, flagged if CISA lists them as actively exploited. Matching packages are pinned to the top of results. No manual upkeep.

Static site (GitHub Pages, `docs/`). Parser tests: `cd test && node run2.mjs`.
