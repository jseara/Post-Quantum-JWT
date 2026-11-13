# Sprint 2 results: where large tokens break in transport

Measured boundaries for JWTs carried through Chromium → nginx → waitress → application (stack and setup: [TRANSPORT.md](TRANSPORT.md); tasks: [PROGRESS.md](PROGRESS.md#sprint-2-find-where-large-tokens-break-in-transport)). This document covers the cookie transport (S2-04). The Bearer header transport (S2-05) is not measured yet.

Every number below comes from one of these WSL2 runs (Ubuntu 24.04.4, x86_64, 4 KiB memory pages; Chromium 156.0.8078.4, nginx 1.31.8, waitress 3.0.2), recorded on November 13, 2026 at commit `0c7eec0`:

| Run | Claims | Cookie attributes | nginx response buffers | Data |
| --- | --- | --- | --- | --- |
| Default | minimal | `Path=/; HttpOnly; SameSite=Strict` | defaults (one 4 KiB page) | [sweep.json](results/transport/20261113T074114Z-wsl2/cookie-default/sweep.json), [logs](results/transport/20261113T074114Z-wsl2/cookie-default/logs/), [nginx.conf](results/transport/20261113T074114Z-wsl2/cookie-default/nginx.conf) |
| Pinned | minimal | same | `--proxy-buffers 16k` | [sweep.json](results/transport/20261113T074114Z-wsl2/cookie-16k/sweep.json), [logs](results/transport/20261113T074114Z-wsl2/cookie-16k/logs/), [nginx.conf](results/transport/20261113T074114Z-wsl2/cookie-16k/nginx.conf) |
| ML-DSA-44 OIDC, default | oidc | `Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600` | defaults | [sweep.json](results/transport/20261113T074114Z-wsl2/mldsa-oidc-default/sweep.json), [logs](results/transport/20261113T074114Z-wsl2/mldsa-oidc-default/logs/), [nginx.conf](results/transport/20261113T074114Z-wsl2/mldsa-oidc-default/nginx.conf) |
| ML-DSA-44 OIDC, pinned | oidc | same | `--proxy-buffers 16k` | [sweep.json](results/transport/20261113T074114Z-wsl2/mldsa-oidc-16k/sweep.json), [logs](results/transport/20261113T074114Z-wsl2/mldsa-oidc-16k/logs/), [nginx.conf](results/transport/20261113T074114Z-wsl2/mldsa-oidc-16k/nginx.conf) |

`--proxy-buffers 16k` sets `proxy_buffer_size 16k; proxy_buffers 8 16k;`, which are nginx's defaults on a 16 KiB-page system such as the team's Apple Silicon Mac, so the pinned run reproduces the Mac's nginx configuration on WSL2. Each probe is a fresh browser context that loads the test page through nginx, `fetch()`es `/api/token/issue` (the app answers with a `Set-Cookie`), reads the cookie jar, and `fetch()`es `/api/token/verify`; the same token is also verified directly at the application. Sizes are grown with the `pad` claim of [scripts/token_sizing.py](scripts/token_sizing.py), probed in 512-byte steps up to 24,576 bytes (128-byte steps up to 6,144 for the OIDC runs), and every change of outcome is narrowed to one character of padding.

## Cookie boundaries

"Largest verified" is the largest token that reached the application through the browser and verified. "First rejected" is the next probe up. Byte counts at the boundary are listed under [Byte accounting](#byte-accounting).

| Configuration | Smallest token | Default: largest verified | Default: first rejected (layer, behavior) | Pinned: largest verified | Pinned: first rejected (layer, behavior) |
| --- | ---: | ---: | --- | ---: | --- |
| RS256 | 464 | 3,915 | 3,916: nginx, issue fails (see [exact fill](#nginx-at-exactly-a-full-buffer)) | 4,092 | 4,094: Chromium, cookie not stored |
| ES256 | 208 | 3,915 | 3,916: nginx, issue fails | 4,092 | 4,094: Chromium, cookie not stored |
| EdDSA | 208 | 3,915 | 3,916: nginx, issue fails | 4,092 | 4,094: Chromium, cookie not stored |
| ML-DSA-44 | 3,355 | 3,915 | 3,917: nginx, 502 | 4,093 | 4,094: Chromium, cookie not stored |
| SLH-DSA-SHA2-128s | 10,613 | none | 10,613: nginx, 502 | none | 10,613: Chromium, cookie not stored |
| SLH-DSA-SHA2-128f | 22,922 | none | 22,922: nginx, 502 | none | 22,922: nginx, 502 |
| ML-DSA-44, OIDC claims, full attributes | 4,095 | none | 4,095: nginx, 502 | none | 4,095: Chromium, cookie not stored |

The boundaries are the same for every configuration that can reach them, because each limit counts bytes, not algorithms. The one-byte differences come from base64url: a payload segment never has a length of 4n + 1, so RS256, ES256, and EdDSA cannot produce a 4,093-byte token with these claims, while ML-DSA-44 can (and cannot produce 3,916).

**Default buffers (WSL2).** nginx is the first and only cookie limit. It rejects the application's response once its header block (status line, every header line, and the final CRLF) reaches 4,096 bytes, the default `proxy_buffer_size` on a 4 KiB-page system: 4,095 bytes passes and anything larger fails. With the default attributes that happens at a 3,916-byte token, before Chromium's cookie limit (a 4,093-byte token) is reached, so on this machine Chromium's limit is never the one that binds. Above the boundary, nginx answers `502 Bad Gateway` and logs `upstream sent too big header`, while `app.log` shows the application answered 200.

**Pinned buffers (16k).** Chromium is the first limit: it stores a cookie whose name + value is 4,096 bytes and silently drops one of 4,097 (`jwt` + a 4,093- or 4,094-byte token); the issue response is a normal 200 and the browser shows no error. nginx becomes the rejecting layer again once the response header block reaches 16,384 bytes (a 16,204-byte token), which is the second boundary the sweep found. Between 4,094 and 16,203 bytes the cookie is rejected by Chromium; from 16,204 bytes by nginx.

**Post-quantum tokens.** ML-DSA-44 with the minimal Sprint 1 claims fits with 738 bytes to spare under Chromium's limit (3,355 of 4,093), or 560 bytes under WSL2's default nginx buffer. Neither SLH-DSA parameter set can be carried in a cookie at any size: its smallest token is already above every limit.

## ML-DSA-44 claim headroom

With typical OpenID Connect ID token claims ([fixtures/claims_oidc.json](fixtures/claims_oidc.json): 22 claims, 618 bytes of compact JSON) and production cookie attributes, the **unpadded ML-DSA-44 token is 4,095 bytes, so `jwt` + token is 4,098 bytes: 2 bytes over Chromium's 4,096-byte limit before any extra claim.** The headroom is negative at both buffer settings:

- **Pinned (16k), the Mac's defaults:** Chromium drops the cookie. The claims would have to shrink by at least 2 bytes of token to fit, and any additional claim breaks it again.
- **Default (WSL2):** nginx rejects first with 502, because the 4,156-byte `Set-Cookie` value makes a 4,297-byte response header block. From the boundary above, the token would have to be at most about 3,893 bytes (3,915 minus the 22 bytes the extra `Secure; ` and `; Max-Age=3600` attributes add); this figure is derived from the default-attribute boundary, not measured.

`Secure` cookies are stored and sent on `http://127.0.0.1` (Chromium treats loopback as a secure context), so these attributes behave as on an HTTPS site; `tests/test_transport_sweep.py` checks this.

## nginx at exactly a full buffer

When the upstream response header block is **exactly** `proxy_buffer_size` bytes (4,096 by default, 16,384 pinned), nginx does not answer 502. It forwards the `200` status line and headers, including the `Set-Cookie`, and then loses the body: `proxy-error.log` records `upstream prematurely closed connection while reading upstream`, `proxy-access.log` logs `200` with 0 body bytes, and Chromium reports `net::ERR_CONTENT_LENGTH_MISMATCH`, so `fetch()` fails with `TypeError: Failed to fetch`. Chromium still stores the cookie, and the next request verifies. It happened at the RS256, ES256, and EdDSA boundary (a 3,916-byte token) in the default run and at 16,204 bytes in the pinned run, and was reproducible 5 times out of 5 in a separate check; one byte smaller works normally and one byte larger gets a clean 502. The sweep counts it as a rejection by nginx, because the issue request failed. A client that ignores the failed response but keeps the cookie would see a token "issued" through an error.

## Byte accounting

Each probe in `sweep.json` records, under `bytes`, the size each limit counts. At the boundaries of the default and pinned runs (RS256, ES256, and EdDSA are identical; ML-DSA-44 differs by one byte):

| Probe | Token | Cookie name + value (Chromium: 4,096) | `Set-Cookie` value | Upstream response header block (nginx: `proxy_buffer_size`) | `Cookie:` line (nginx: 8,192) | Request headers, as Chromium reported | Request headers, as the app received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Default, largest verified | 3,915 | 3,918 | 3,954 | 4,095 | 3,929 | 4,553 | 4,456 |
| Default, first rejected (exact fill) | 3,916 | 3,919 | 3,955 | 4,096 | 3,930 | 4,554 | 4,457 |
| Pinned, largest verified (ML-DSA-44) | 4,093 | 4,096 | 4,132 | 4,273 | 4,107 | 4,731 | 4,634 |
| Pinned, first rejected | 4,094 | 4,097 | 4,133 | 4,274 | — (not sent) | — | — |
| OIDC ML-DSA-44, full attributes | 4,095 | 4,098 | 4,156 | 4,297 | — (not sent) | — | — |

How each is counted, so the figures can be checked by hand:

- **Cookie name + value:** `len("jwt") + token`, the quantity Chromium's `kMaxCookieNamePlusValueSize` limits; `=` and attributes are not counted.
- **`Set-Cookie` value:** `jwt=<token>; <attributes>`, as the application sends it (39 bytes more than the token with the default attributes, 61 with the full ones).
- **Upstream response header block:** the application's status line, every `Name: value\r\n`, and the final `\r\n`, measured from a direct request to the application with the same parameters. This is what nginx must fit in `proxy_buffer_size`.
- **`Cookie:` line:** `Cookie: jwt=<token>\r\n`, the line nginx must fit in one `large_client_header_buffers` buffer. It never comes near 8,192 bytes, because Chromium caps the cookie first.
- **Request headers:** the request line plus every header line and the final CRLF, from the headers Chromium reported to Playwright (`browser.log`) and from the WSGI environ at the application (which drops hop-by-hop headers and has `Host` as nginx rewrote it). They differ by 97 bytes in every verified probe.
- Rejected probes show no request bytes because no cookie was sent; the next request carries only the page's ordinary headers (624 bytes as Chromium reported them).

## Reproduce

From a clean checkout with the environment from [TRANSPORT.md](TRANSPORT.md#setup):

```bash
python scripts/transport_stack.py sweep --output-dir results/transport/<run>/cookie-default
python scripts/transport_stack.py sweep --proxy-buffers 16k --output-dir results/transport/<run>/cookie-16k
python scripts/transport_stack.py sweep --alg ML-DSA-44 --claims oidc --attrs full --step 128 --max-bytes 6144 --output-dir results/transport/<run>/mldsa-oidc-default
python scripts/transport_stack.py sweep --alg ML-DSA-44 --claims oidc --attrs full --step 128 --max-bytes 6144 --proxy-buffers 16k --output-dir results/transport/<run>/mldsa-oidc-16k
```

or `make sweep` for the first two. The four runs took about 5 minutes on the WSL2 machine. Each run directory holds `sweep.json` (settings, every probe with its outcome, rejecting layer, evidence, nonces, and byte counts, and the boundaries), the four logs (`browser.log`, `proxy-access.log`, `proxy-error.log`, `app.log`), and the rendered `nginx.conf`. Every probe's issue and verify nonces can be found in each layer's log.

## Limitations

- **One machine.** These runs are from WSL2. The pinned run reproduces the Mac's nginx buffers, and the Mac's earlier `tokens` run agrees with it (the SLH-DSA-SHA2-128s cookie was dropped by Chromium there), but the sweep itself has not been run on macOS.
- **One browser, HTTP/1.1, no TLS.** Only Chromium was tested. HTTPS and HTTP/2, where header compression changes how nginx and Chromium apply their limits, are proposed for Sprint 3.
- **One cookie.** Each probe sends a single `jwt` cookie. Real sites send other cookies alongside it, which count toward nginx's 8,192-byte `Cookie:` line and its total header buffers, but not toward Chromium's per-cookie limit. Cookie splitting is Sprint 3 work (S3-02).
- **Monotonic search.** Between coarse probes the sweep assumes the outcome changes only once; every boundary was confirmed by a probe on each side, and the exact-fill case was found because it is a different outcome.
- **Derived figure.** The 3,893-byte limit for OIDC claims with full attributes at WSL2's defaults is calculated from the measured default-attribute boundary, not probed.

## Not yet measured

- **S2-05, Bearer header transport:** the same sweep with `Authorization: Bearer`, sent from the browser and from a non-browser client, with the first rejecting limit raised once to find the next.
