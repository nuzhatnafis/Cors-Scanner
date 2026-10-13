# Cors-Scanner
Tests an endpoint against a set of attacker-controlled `Origin` headers
(arbitrary origin, null origin, subdomain-prefix/suffix bypass tricks,
scheme downgrade) and flags dangerous `Access-Control-Allow-Origin` /
`Access-Control-Allow-Credentials` combinations.

## ⚠️ Legal / Ethical Use

Only run this against targets you own or are explicitly authorized to
test.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python cors_scanner.py https://api.target.com/me --target-host target.com

# With an auth cookie, to test an authenticated endpoint
python cors_scanner.py https://api.target.com/me --target-host target.com \
  --header "Cookie: session=abc123"
```

## What it tests

| Origin sent | Checks for |
|---|---|
| `https://evil-attacker.com` | Server reflects *any* origin back |
| `null` | Server trusts the `null` origin (exploitable via sandboxed iframes / `file://`) |
| `https://{target}.evil-attacker.com` | Naive `startswith`/`endswith` origin validation |
| `https://evil-attacker.com.{target}` | Naive substring (`in`) origin validation |
| `http://{target}` (downgraded scheme) | Server doesn't enforce HTTPS-only origins |

## Severity logic

- **Critical** — `Access-Control-Allow-Origin: *` with `Allow-Credentials: true` (invalid per spec, but seen in the wild)
- **High** — attacker origin reflected AND credentials allowed → full authenticated data theft
- **Medium** — attacker origin reflected, no credentials flag
- **Low** — wildcard ACAO only (fine if the endpoint truly serves public data)

## Example output

```
[*] Testing Origin: https://evil-attacker.com  (Arbitrary unrelated origin)
    -> ACAO: 'https://evil-attacker.com', ACAC: 'true'
    [HIGH] 'Arbitrary unrelated origin' is reflected back in Access-Control-Allow-Origin
    WITH Allow-Credentials: true — any site can read authenticated responses from this
    endpoint on behalf of a logged-in victim.
```

## Confirming a finding

A positive result here means the *headers* look exploitable. To fully
confirm, host a tiny test page on an origin you control that does:

```js
fetch("https://api.target.com/me", { credentials: "include" })
  .then(r => r.text()).then(console.log);
```

and verify it actually returns the victim's authenticated data.

## Ideas to extend

- Add `Access-Control-Allow-Methods`/`Allow-Headers` preflight (`OPTIONS`) analysis
- Add a check for the `Vary: Origin` header (its absence can cause cache poisoning)
- Auto-generate the PoC HTML test page from a positive finding

## License

MIT
