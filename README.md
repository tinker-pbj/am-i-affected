# Am I Affected?

Paste a lockfile and see which known vulnerabilities hit your dependencies, plus this week's headline bugs.

- Runs entirely in the browser: the lockfile is parsed client-side, and only package names + versions are sent to [OSV.dev](https://osv.dev).
- Supported: package-lock.json, yarn.lock (v1 + berry), pnpm-lock.yaml, Gemfile.lock, poetry.lock, uv.lock, Pipfile.lock, pinned requirements.txt, Cargo.lock, go.sum / go.mod, composer.lock.
- "This week" (`docs/named.js`) is curated by hand from vendor advisories, since new bugs often reach OSV days later and servers (nginx, JDK) aren't packages. Each entry links to the original advisory.

Static site (GitHub Pages, `docs/`). Parser tests: `cd test && node run.mjs`.
