# Noyra

Noyra is a support workspace for reusable chat replies. Its Floater keeps saved scripts beside a CRM for quick copy and paste.

## Project files

- `index.html` - landing page and signed-in script manager.
- `css/site.css` - the single stylesheet, grouped into labeled sections.
- `js/noyra.js` - Floater, chat, and shared interface behavior.
- `js/noyra-auth.js` - account and API client.
- `js/noyra-workspace.js` - topic boxes and saved scripts.
- `server.py` - local account API and SQLite persistence.
- `scripts/verify_ui.py` - browser UI verification helper.
- `scripts/create_user_no_recovery.py` - account creation helper for EC2 staging.
- `deploy/ec2/` - Nginx and systemd staging configuration.

## Run locally

Start the local API:

```bash
python server.py
```

Open `http://127.0.0.1:8000` in Chrome or Edge. The first run creates `data/noyra.sqlite3`. The `data/` directory is excluded from source control and should be backed up separately if it contains accounts you need.

## Accounts and recovery

Registration uses first and last name, username, password confirmation, and three recovery questions (one from each group). It does not use email or SMS verification. Passwords must be at least 8 characters. Passwords and recovery answers are salted and hashed with scrypt; sign-in and recovery attempts are rate-limited, and sessions use an HttpOnly, SameSite cookie.

Recovery questions can be guessed or discovered, so they are weak identity checks. For a public service, prefer one-time recovery codes or another recovery factor. See [NIST guidance](https://pages.nist.gov/800-63-4/sp800-63b.html) and the [OWASP recovery guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).

## Deployment

`server.py` uses Python's built-in development server and is for local evaluation or staging. Do not expose it directly to the public internet. Public use needs HTTPS, a production application server or managed auth service, protected persistent database storage, backups, and monitoring.

For the EC2 staging setup, see [`deploy/ec2/README.md`](deploy/ec2/README.md). Behind a trusted TLS proxy, set `NOYRA_PUBLIC_ORIGIN` to the public origin and `NOYRA_TRUST_PROXY=1`. Keep the database outside the web root.
