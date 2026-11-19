"""Build docs/recent.json: critical advisories published in the last DAYS days, from OSV's public bucket.

For each ecosystem, read modified_id.csv (newest first), fetch the recently modified advisories, and keep those that
were *published* recently and are CRITICAL (advisory severity, or CVSS v3 base score >= 9). Advisories that CISA lists
as known exploited are flagged. Standard library only, so it runs anywhere (GitHub Actions).
"""
import concurrent.futures as cf, csv, datetime as dt, io, json, math, sys, urllib.request

DAYS = 14
ECOS = ['npm', 'PyPI', 'RubyGems', 'crates.io', 'Go', 'Packagist', 'Maven', 'NuGet']
BUCKET = 'https://osv-vulnerabilities.storage.googleapis.com'
KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
now = dt.datetime.now(dt.timezone.utc)
since = now - dt.timedelta(days=DAYS)

def get(url, timeout=30):
    req = urllib.request.Request(url, headers={'user-agent': 'am-i-affected (github.com/tinker-pbj/am-i-affected)'})
    with urllib.request.urlopen(req, timeout=timeout) as r: return r.read()

def parse_time(s):
    try: return dt.datetime.fromisoformat(s.replace('Z', '+00:00'))
    except Exception:
        try: return dt.datetime.strptime(s[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=dt.timezone.utc)
        except Exception: return None

def cvss3(vec):
    m = dict(p.split(':') for p in vec.split('/')[1:] if ':' in p)
    W = {'AV': {'N': .85, 'A': .62, 'L': .55, 'P': .2}, 'AC': {'L': .77, 'H': .44}, 'UI': {'N': .85, 'R': .62}, 'CIA': {'H': .56, 'L': .22, 'N': 0}}
    S = m.get('S') == 'C'
    try:
        PR = {'N': .85, 'L': .68 if S else .62, 'H': .5 if S else .27}[m['PR']]
        iss = 1 - (1 - W['CIA'][m['C']]) * (1 - W['CIA'][m['I']]) * (1 - W['CIA'][m['A']])
        imp = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if S else 6.42 * iss
        ex = 8.22 * W['AV'][m['AV']] * W['AC'][m['AC']] * PR * W['UI'][m['UI']]
    except KeyError: return 0
    if imp <= 0: return 0
    return math.ceil(min(1.08 * (imp + ex) if S else imp + ex, 10) * 10 - 1e-9) / 10

def is_critical(v):
    s = (v.get('database_specific') or {}).get('severity', '')
    if isinstance(s, str) and s.upper() == 'CRITICAL': return True
    if isinstance(s, str) and s.upper() in ('HIGH', 'MODERATE', 'MEDIUM', 'LOW'): return False
    return any(x.get('score', '').startswith('CVSS:3') and cvss3(x['score']) >= 9 for x in v.get('severity') or [])

try: kev = {x['cveID'] for x in json.loads(get(KEV, 60))['vulnerabilities']}
except Exception as e: print('KEV unavailable:', e, file=sys.stderr); kev = set()

out = []
for eco in ECOS:
    try: rows = list(csv.reader(io.StringIO(get(f'{BUCKET}/{eco}/modified_id.csv', 60).decode())))
    except Exception as e: print(eco, 'skipped:', e, file=sys.stderr); continue
    ids = [r[1] for r in rows if len(r) == 2 and (parse_time(r[0]) or since) >= since and not r[1].startswith('MAL-')][:3000]
    def fetch(i):
        try: return json.loads(get(f'{BUCKET}/{eco}/{i}.json'))
        except Exception: return None
    with cf.ThreadPoolExecutor(24) as ex: vulns = [v for v in ex.map(fetch, ids) if v]
    n = 0
    for v in vulns:
        pub = parse_time(v.get('published', ''))
        if not pub or pub < since or v.get('withdrawn') or not is_critical(v): continue
        aliases = v.get('aliases') or []
        cve = next((a for a in aliases if a.startswith('CVE-')), None)
        pkgs = sorted({a['package']['name'] for a in v.get('affected', []) if a.get('package', {}).get('ecosystem') == eco})
        if not pkgs: continue
        out.append({'id': v['id'], 'cve': cve, 'ecosystem': eco, 'packages': pkgs[:20], 'summary': (v.get('summary') or v.get('details', '')[:160]).strip(),
                    'published': pub.date().isoformat(), 'exploited': bool(cve and cve in kev)})
        n += 1
    print(f'{eco}: {len(ids)} recently modified, {n} new critical', file=sys.stderr)

out.sort(key=lambda x: (not x['exploited'], x['published']), reverse=False)
out.sort(key=lambda x: x['published'], reverse=True)
out.sort(key=lambda x: not x['exploited'])
json.dump({'generated': now.isoformat(timespec='minutes'), 'days': DAYS, 'advisories': out}, open('docs/recent.json', 'w'), indent=1)
print(len(out), 'critical advisories in the last', DAYS, 'days', file=sys.stderr)
