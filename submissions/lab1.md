# Lab 1 — Submission

## Triage report

### Asset
- **Image tag:** `bkimminich/juice-shop:v20.0.0`
- **Image digest:** `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- **Host OS:** Linux Mint 21.3 (kernel 6.8.0-90-generic)
- **Docker version:** Docker 28.0.1, build 068a01e

Pulling the pinned image and reading its registry digest:

![docker run pulling the pinned image and printing its sha256 digest](../screenshots/Screenshot%20from%202026-09-14%2000-38-51.png)

![docker inspect showing the RepoDigests sha256 value](../screenshots/Screenshot%20from%202026-09-14%2000-45-40.png)

### Deployment
- **Run command:**
  ```bash
  docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
  ```
- **Access URL:** http://127.0.0.1:3000
- **Port binding:** Bound to localhost only (`127.0.0.1:3000->3000/tcp`). This matters because Juice Shop is vulnerable by design; binding to `127.0.0.1` keeps it reachable only from this machine. A bare `-p 3000:3000` would publish it on every network interface, exposing a deliberately insecure app to anyone on the same network (e.g. campus/dorm Wi-Fi).
- **Restart policy:** `no` (container is not set to auto-restart).

### Health
- **HTTP code on `/`:** `HTTP 200`
- **Version output:** `{"version":"20.0.0"}` (from `/rest/admin/application-version`)
- **Product count:** `46` (from `/api/Products`, `.data | length`)
- **`docker ps` line:**
  ```
  NAMES        STATUS          PORTS
  juice-shop   Up 47 minutes   127.0.0.1:3000->3000/tcp
  ```

`docker ps` (localhost-only port binding), HTTP `200`, version and product-count checks:

![docker ps showing juice-shop up and bound to 127.0.0.1:3000](../screenshots/Screenshot%20from%202026-09-14%2000-40-10.png)

![curl returning HTTP 200 and version 20.0.0](../screenshots/Screenshot%20from%202026-09-14%2000-42-27.png)

![curl to /api/Products piped through jq returning 46](../screenshots/Screenshot%20from%202026-09-14%2000-43-41.png)

### Surface (the five things from 1.2)
- **Login & registration:** Both are reachable from the Account menu (top right) with no authentication. Registration (`POST /api/Users/`) accepts a security question/answer and returns the new user record (id, email, role) with HTTP `201 Created`. The password is sent in the request body and, because the app runs over plain HTTP locally, travels in cleartext — acceptable on localhost but unsafe in production. The password is *not* echoed back in the response, which is good.
- **Products:** The catalog holds 46 products, served from `/api/Products` (capital P, `{"data":[...]}` envelope). Product data and product reviews (`/api/Products/<id>/reviews`) are returned without any authentication — the browser fetches them anonymously.
- **Admin / account area:** `GET /rest/admin/application-configuration` returns the full application configuration to an unauthenticated browser despite `admin` in the path. It exposes the base URL, application settings and OAuth client id / redirect URIs. The OAuth client id is not itself a secret, but a public `/admin/…` config endpoint is worth reviewing for information disclosure.

  ![Browser retrieving /rest/admin/application-configuration and exposing the config object](../screenshots/Screenshot%20from%202026-09-14%2001-16-49.png)
- **Console errors / warnings:** DevTools shows a browser warning that the password `<input>` is not wrapped in a `<form>` element (and at one point reported `type="text"` rather than `type="password"`, consistent with a show-password toggle). This is a usability/standards warning (affects password managers, autofill, accessibility), not a security finding in itself. The console also logged a `POST /rest/user/login 401 (Unauthorized)` from a failed login attempt.

  ![DevTools console: password field not in a form warning and a 401 on POST /rest/user/login](../screenshots/Screenshot%20from%202026-09-14%2000-49-01.png)
- **Local storage & cookies:** After registering, the security answer is submitted separately via `POST /api/SecurityAnswers/` with a client-supplied `UserId: 24`. The server stores the answer hashed (`"answer":"2cae78a7f2…"`), which is good, but the client controlling `UserId` is worth testing for IDOR/broken access control (could a request set another user's security answer?). Registration also spans two separate requests (create user, then create security answer), so a failure of the second leaves an account without a security answer — a consistency concern.

### Headers
`curl -sI http://127.0.0.1:3000 | head -20`:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sun, 13 Sep 2026 21:37:44 GMT
ETag: W/"26af-1a09cb46bb7"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Sun, 13 Sep 2026 22:25:22 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

![Terminal output of curl -sI showing the response headers](../screenshots/Screenshot%20from%202026-09-14%2000-55-46.png)

| Security header | Present? | Value |
|---|---|---|
| Content-Security-Policy | ❌ Missing | — |
| Strict-Transport-Security | ❌ Missing | — |
| X-Content-Type-Options | ✅ Present | `nosniff` |
| X-Frame-Options | ✅ Present | `SAMEORIGIN` |

**Missing:** `Content-Security-Policy` and `Strict-Transport-Security`. (`Strict-Transport-Security` is an HTTPS-only header, so its absence over plain HTTP on localhost is expected — but it is still marked missing for the header check.) Missing security headers fall under **A02 Security Misconfiguration**.

### Top 3 risks
1. **Missing Content-Security-Policy (and HSTS) — A02 Security Misconfiguration.** With no CSP, the browser has no allowlist for scripts, so any injected content (e.g. via a stored/reflected XSS) runs freely; CSP is a key defense-in-depth control against XSS. Missing HSTS means a client is not forced onto HTTPS, leaving room for downgrade/man-in-the-middle attacks in a real deployment.
2. **Sensitive endpoints exposed without authentication — A01 Broken Access Control.** `/rest/admin/application-configuration` returns full app configuration to any anonymous visitor, and `POST /api/SecurityAnswers/` trusts a client-supplied `UserId`. If the backend does not verify ownership, an attacker could set or read data tied to another user's id — a classic IDOR / broken access control issue that is the most valuable thing to test next.
3. **Cleartext transport of credentials — A04 Insecure Design / A02 Security Misconfiguration.** The app is served over plain HTTP, so login and registration passwords and security answers travel unencrypted. On localhost this is only a lab concern, but the same posture in production would expose credentials to network eavesdropping; combined with the missing HSTS header there is nothing forcing an encrypted channel.

## GitHub community

**Stars:** starred the course repository ([inno-devops-labs/DevSecOps-Intro](https://github.com/inno-devops-labs/DevSecOps-Intro)) and [simple-container-com/api](https://github.com/simple-container-com/api).

**Follows:** professor [@Cre-eD](https://github.com/Cre-eD), TAs [@Naghme98](https://github.com/Naghme98) and [@pierrepicaud](https://github.com/pierrepicaud), and classmates [@ivanovvaak](https://github.com/ivanovvaak), [@AlexToday111](https://github.com/AlexToday111) and [@Mukhin-I](https://github.com/Mukhin-I).

Stars are the clearest public signal of a project's value: they help maintainers gauge adoption and interest, raise the project's visibility in search and trending so more people discover it, and provide the social proof that attracts contributors and sponsors — all as unpaid recognition for volunteer work. Following people keeps a team's work visible in one feed, so I see classmates' new repos, pushes and pull requests as they happen, which makes it easier to review each other's code, coordinate on shared labs, and learn from how teammates solve problems.

## PR template

- **File path:** `.github/PULL_REQUEST_TEMPLATE.md`
- **Sections:** Goal, Changes, Testing, Artifacts & Screenshots
- **Checklist items:**
  - Title follows `feat(labN): <topic>`
  - No secrets or large temp files committed
  - `submissions/labN.md` exists

**Auto-filled draft PR:** <!-- TODO: paste the draft PR link here after pushing, or add a screenshot showing the description box pre-filled with the template -->

## Bonus: CI smoke test

- **Workflow path:** `.github/workflows/lab1-smoke.yml`
- **Run URL:** <!-- TODO: paste the GitHub Actions run URL from the draft PR after pushing -->
- **Run duration:** <!-- TODO: fill in the run duration shown in the Actions run -->
- **curl output excerpt (from the job log):**
  ```
  <!-- TODO: paste the log line, e.g. {"version":"20.0.0"} and "Juice Shop is up after Ns" -->
  ```
