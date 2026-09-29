# Hardening & Real-World Realism

VulNet is a lab, but its perimeter now behaves like a real banking API. Lab conveniences are
explicit, switchable, and **off** in `VULNET_ENV=hardened`.

| Control | Behaviour | Setting |
|---|---|---|
| Server-side security mode | Mode comes from `SECURITY_MODE`. A client asking for `vulnerable` gets **403** unless overriding is allowed. | `VULNET_ALLOW_MODE_OVERRIDE` (on in `local_lab`; always off in `hardened`) |
| MFA code delivery | The code is only returned by `/auth/login` for the demo (no SMS/email channel). Hardened mode omits it. | `VULNET_EXPOSE_MFA_CODE` |
| Session IDs | Random (`SESSION-` + 64 bits from `secrets`), no longer sequential. | — |
| Session expiry | Sessions expire after a TTL and are invalidated on next use. | `VULNET_SESSION_TTL_SECONDS` (1800) |
| Login throttling | Failed passwords and failed MFA codes count per account; lockout returns **429** with `Retry-After`. | `VULNET_MAX_FAILED_LOGINS` (5), `VULNET_LOCKOUT_SECONDS` (900) |
| `/security/evaluate` | Requires an authenticated session; identity and role come from the session, not the request body. | — |
| CORS | Explicit origin allow-list, limited methods and headers; no wildcard with credentials. | `VULNET_CORS_ORIGINS` |
| Response headers | `nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`. | — |
| Opening balance | Read from the simulated domain service instead of hard-coded values. | — |
| Audit log | `logs/audit.jsonl` is no longer tracked in git. | `.gitignore` |

Settings live in `security/settings.py` and are read on every call; `.env` is loaded automatically.

## Running hardened
```bash
VULNET_ENV=hardened uvicorn api.main:app --port 8000
```
In this mode the demo login no longer reveals the MFA code, so sign in through the API with a code you obtain out of band.

## Known limits (still a lab)
- Users, sessions, MFA challenges and lockout counters are in memory: lost on restart, single worker only.
- Threat detection is signature based (`security/threat_detector.py`); paraphrased or multilingual attacks can evade it. This is intentional teaching material.
- No TLS termination, no rate limiting beyond login lockout, no external identity provider.
