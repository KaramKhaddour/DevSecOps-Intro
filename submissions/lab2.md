# Lab 2 — Submission

## Task 1

### Severity counts (2.2)

`jq 'length'` → **23 risks total**.

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | **23** |

### Top five risks, ranked (2.3)

| # | Severity | Rule (category) | Most relevant asset |
|---|---|---|---|
| 1 | elevated | `cross-site-scripting` | juice-shop |
| 2 | elevated | `missing-authentication` | juice-shop |
| 3 | elevated | `unencrypted-communication` | user-browser |
| 4 | elevated | `unencrypted-communication` | reverse-proxy |
| 5 | medium | `cross-site-request-forgery` | juice-shop |

### STRIDE mapping

| # | Rule | STRIDE | Why |
|---|---|---|---|
| 1 | `cross-site-scripting` | **T** (Tampering) | Injected script tampers with the page the app serves, altering content and actions in another user's authenticated session. |
| 2 | `missing-authentication` | **S + E** (Spoofing + Elevation of Privilege) | With no authentication, anyone can act as any identity (spoofing), and reaching a protected endpoint with no check in place is elevation of privilege. |
| 3 | `unencrypted-communication` (user-browser) | **I** (Information Disclosure) | Cleartext HTTP over this link lets anyone on the path read the traffic, disclosing credentials and session data in transit. |
| 4 | `unencrypted-communication` (reverse-proxy) | **I** (Information Disclosure) | The proxy-side link is also cleartext, so the same data is exposed to eavesdropping on the internal hop. |
| 5 | `cross-site-request-forgery` | **S** (Spoofing) | A forged cross-site request is executed with the victim's identity, so the server acts on a request that only appears to come from the legitimate user. |

### A trust-boundary-crossing arrow from the top five

In `data-flow-diagram.png`, the **`http` arrow from User Browser → Juice Shop Application** crosses the **Internet → Host / Container Network** trust boundary (from the untrusted `Internet (network-dedicated-hoster)` boundary straight into the application inside `Container Network`). It is the arrow behind top-five risks #2/#3 (`unencrypted-communication` on `user-browser`).

It is worth an attacker's time because it carries login credentials, session tokens and every request/response in **plaintext `http`** as it leaves the client and crosses the most exposed boundary in the model. An attacker positioned anywhere on that path (shared Wi‑Fi, a rogue router, ARP/DNS spoofing) can passively read the traffic to steal credentials and session tokens, or actively modify it — for a deliberately vulnerable target like Juice Shop, that single unencrypted hop yields account takeover without touching the application logic at all.

## Task 2

### Baseline vs secure, per severity

| Severity | Baseline | Secure | Delta |
|---|---|---|---|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | **-3** |
| Medium | 14 | 12 | **-2** |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **-5** |

Total dropped from 23 to 18 (~22%, roughly a fifth), not to zero.

### Rules in `gone:` and the field change that removed each

| Rule ID (gone) | Field change that removed it |
|---|---|
| `unencrypted-communication` | Both inbound links to `juice-shop` changed from `protocol: http` to `protocol: https` (browser→app *Direct to App*, and reverse-proxy→app *To App*). |
| `unencrypted-asset` | `encryption: none` → `encryption: data-with-symmetric-shared-key` on both `juice-shop` (application) and `persistent-storage` (datastore), i.e. encryption at rest. |
| `missing-authentication` | Reverse-proxy→`juice-shop` link `authentication: none` → `authentication: session-id`, so the inbound link now declares how it authenticates. |

`new:` was empty — no new rule categories appeared in the secure model.

### Two rules that still fire, and why the edits could not remove them

- **`cross-site-scripting` (elevated, juice-shop).** This is an application-code weakness (missing output encoding / no CSP), inherent to a custom-developed internet-facing web app. Threagile flags it from the asset's technology and `custom_developed_parts: true`, so no transport-protocol, encryption, or link-authentication attribute can clear it — only fixing the code or adding a WAF/CSP would.
- **`cross-site-request-forgery` (medium, juice-shop).** CSRF is a property of how the app handles state-changing, session-authenticated requests, not of the channel. Encrypting the link or declaring its authentication does not add anti-CSRF tokens, so the rule keeps firing regardless of my YAML edits.

### What risk is left, and what it would take to close it

The five risks my edits removed were all channel/at-rest properties I could express directly in the model (cleartext transport, unencrypted storage, an undeclared inbound authentication). What remains is mostly **application-level and process/architecture risk**: XSS and CSRF in Juice Shop's own code, missing second factor, no WAF, no secrets vault or identity store, container base-image trust, and host hardening. Closing these needs real controls, not model attributes — secure coding with output encoding and a CSP, anti-CSRF tokens, a deployed WAF, a secrets vault, hardened and digest-pinned base images, and enforced 2FA. One that **no YAML edit can close is `cross-site-scripting`**: Juice Shop is vulnerable by design, so the flaw lives in the application source; a threat model can only surface it, never attribute it away.
