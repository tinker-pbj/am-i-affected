// This week's named vulnerabilities. Curated by hand from the vendors' advisories, because brand-new bugs often
// reach the OSV database days later (or never, for servers like nginx and the JDK, which aren't packages).
// Each entry: which product it hits, and a test on that product's version.
window.NAMED = [
  {
    name: 'Ruby2Shell', ids: ['GHSA-34m4-m9fh-gqp5'], product: 'ruby', severity: 'CRITICAL', date: '2026-11-18',
    what: 'Pre-auth remote code execution in Ruby string case conversion. Reachable from stock Rails and Sinatra.',
    links: [['Ruby advisory', 'https://www.ruby-lang.org/en/news/2026/11/18/multiple-vulnerabilities-in-regexp-and-string/'], ['Write-up', 'https://verialabs.com/ruby2shell/']],
    fix: 'Upgrade Ruby to 3.3.14, 3.4.13 or 4.0.10 (3.2 and older are end-of-life: move to a supported series).',
    affected(v) { // [major, minor, patch]
      const [a, b, c] = v;
      if (a === 4 && b === 0) return c <= 9;
      if (a === 3 && b === 4) return c <= 12;
      if (a === 3 && b === 3) return c <= 13;
      if (a === 3 && b <= 2) return true;
      if (a === 2 && b >= 4) return true;
      return a < 4 ? null : false;   // null = unknown
    },
  },
  {
    name: 'Nginx HTTP/2 RCE', ids: ['CVE-2026-123007', 'CVE-2026-123633'], product: 'nginx', severity: 'CRITICAL', date: '2026-11-17',
    what: 'Unauthenticated remote code execution in nginx HTTP/2 (flow control memory corruption + use-after-free). Needs HTTP/2 enabled.',
    links: [['Wiz write-up', 'https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities'], ['NGINX2Root', 'https://nginx2root.com/']],
    fix: 'Upgrade nginx to 1.30.7 (stable) or 1.31.9 (mainline). NGINX Plus: R37 P1 or later.',
    affected(v) {
      const [a, b, c] = v;
      if (a !== 1) return null;
      if (b < 9 || (b === 9 && c < 5)) return false;
      if (b === 30) return c < 7;
      if (b === 31) return c < 9;
      return b < 30;   // 1.9.5 … 1.29.x: affected, no fix on those branches
    },
  },
  {
    name: 'Java4Shell', ids: ['CVE-2026-114938'], product: 'java', severity: 'CRITICAL', date: '2026-11-17',
    what: 'Remote code execution via malformed Base64 in OpenJDK (and Temurin, Corretto, Zulu, Oracle Java…). Only on x86-64 CPUs with AVX-512 VBMI.',
    links: [['Write-up', 'https://calif.io/java4shell/']],
    fix: 'Install the November 17, 2026 JDK update. Stopgap: start Java with -XX:-UseBASE64Intrinsics.',
    affected(v) {
      const [a, b, c] = v;   // feature release, interim, update
      if (a === 17) return c >= 6 && c <= 21;
      if (a === 21) return c <= 13;
      if (a === 25) return c <= 5;
      if (a === 27) return c <= 1;
      if (a < 17) return false;
      return null;
    },
  },
];
