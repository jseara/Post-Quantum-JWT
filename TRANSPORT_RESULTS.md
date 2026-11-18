# Sprint 2 results: where large tokens break in transport

Measured boundaries for JWTs carried through Chromium → nginx → waitress → application (stack and setup: [TRANSPORT.md](TRANSPORT.md); tasks: [PROGRESS.md](PROGRESS.md#sprint-2-find-where-large-tokens-break-in-transport)). This document covers the cookie transport (S2-04) and the `Authorization: Bearer` header transport (S2-05).

Every number below comes from one of these WSL2 runs (Ubuntu 24.04.4, x86_64, 4 KiB memory pages; Chromium 156.0.8078.4, nginx 1.31.8, waitress 3.0.2), recorded on November 13, 2026 (the cookie runs at commit `0c7eec0`, the Bearer runs at `e39b3df`):

| Run | Claims | Cookie attributes | nginx response buffers | Data |
| --- | --- | --- | --- | --- |
| Default | minimal | `Path=/; HttpOnly; SameSite=Strict` | defaults (one 4 KiB page) | [sweep.json](results/transport/20261113T074114Z-wsl2/cookie-default/sweep.json), [logs](results/transport/20261113T074114Z-wsl2/cookie-default/logs/), [nginx.conf](results/transport/20261113T074114Z-wsl2/cookie-default/nginx.conf) |
| Pinned | minimal | same | `--proxy-buffers 16k` | [sweep.json](results/transport/20261113T074114Z-wsl2/cookie-16k/sweep.json), [logs](results/transport/20261113T074114Z-wsl2/cookie-16k/logs/), [nginx.conf](results/transport/20261113T074114Z-wsl2/cookie-16k/nginx.conf) |
| ML-DSA-44 OIDC, default | oidc | `Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600` | defaults | [sweep.json](results/transport/20261113T074114Z-wsl2/mldsa-oidc-default/sweep.json), [logs](results/transport/20261113T074114Z-wsl2/mldsa-oidc-default/logs/), [nginx.conf](results/transport/20261113T074114Z-wsl2/mldsa-oidc-default/nginx.conf) |
| ML-DSA-44 OIDC, pinned | oidc | same | `--proxy-buffers 16k` | [sweep.json](results/transport/20261113T074114Z-wsl2/mldsa-oidc-16k/sweep.json), [logs](results/transport/20261113T074114Z-wsl2/mldsa-oidc-16k/logs/), [nginx.conf](results/transport/20261113T074114Z-wsl2/mldsa-oidc-16k/nginx.conf) |
| Bearer, default | minimal | — (Bearer) | defaults (`large_client_header_buffers 4 8k`) | [sweep.json](results/transport/20261113T074114Z-wsl2/bearer-default/sweep.json), [logs](results/transport/20261113T074114Z-wsl2/bearer-default/logs/), [nginx.conf](results/transport/20261113T074114Z-wsl2/bearer-default/nginx.conf) |
| Bearer, raised | minimal | — (Bearer) | `--header-buffers 512k` (`large_client_header_buffers 4 512k`) | [sweep.json](results/transport/20261113T074114Z-wsl2/bearer-512k/sweep.json), [logs](results/transport/20261113T074114Z-wsl2/bearer-512k/logs/), [nginx.conf](results/transport/20261113T074114Z-wsl2/bearer-512k/nginx.conf) |

`--proxy-buffers 16k` sets `proxy_buffer_size 16k; proxy_buffers 8 16k;`, which are nginx's defaults on a 16 KiB-page system such as the team's Apple Silicon Mac, so the pinned run reproduces the Mac's nginx configuration on WSL2. Each probe is a fresh browser context that loads the test page through nginx, `fetch()`es `/api/token/issue` (the app answers with a `Set-Cookie`), reads the cookie jar, and `fetch()`es `/api/token/verify`; a second token with the same claims and padding, issued straight from the application, is also verified directly there. (These runs predate the application's check of every token before issuing it, added after the review of November 16, 2026; the second token is what showed that tokens on the rejected side of a boundary were valid.) Sizes are grown with the `pad` claim of [scripts/token_sizing.py](scripts/token_sizing.py), probed in 512-byte steps up to 24,576 bytes (128-byte steps up to 6,144 for the OIDC runs), and every change of outcome is narrowed to one character of padding.

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

## Bearer header boundaries

Each Bearer probe is sent by two clients: **Chromium**, which `fetch()`es the token in an `Authorization: Bearer` header from the test page (the token is issued in the response body through nginx), and **http.client**, which sends the same header straight to nginx with no browser. The Bearer runs probed 512-byte steps up to 24,576 bytes at the defaults, and 16,384-byte steps up to 327,680 bytes with nginx's header buffers raised.

| Configuration | Smallest token | Default: largest verified (both clients) | Default: first rejected | Raised: largest verified, Chromium | Raised: largest verified, http.client | Raised: first rejected |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| RS256 | 464 | 8,168 | 8,170: nginx, 400 | 261,519 | 261,996 | waitress, 431 |
| ES256 | 208 | 8,168 | 8,170: nginx, 400 | 261,519 | 261,996 | waitress, 431 |
| EdDSA | 208 | 8,168 | 8,170: nginx, 400 | 261,519 | 261,996 | waitress, 431 |
| ML-DSA-44 | 3,355 | 8,167 | 8,169: nginx, 400 | 261,519 | 261,995 | waitress, 431 |
| SLH-DSA-SHA2-128s | 10,613 | none | 10,613: nginx, 400 | 261,519 | 261,996 | waitress, 431 |
| SLH-DSA-SHA2-128f | 22,922 | none | 22,922: nginx, 400 | 261,518 | 261,996 | waitress, 431 |

**Default limits.** nginx is the first limit for both clients, at the same token size. One request header line, from the field name through its CRLF, must fit in one 8,192-byte `large_client_header_buffers` buffer: the largest verified `Authorization: Bearer <token>\r\n` line is 8,192 bytes (an 8,168-byte token), and anything longer gets `400 Request Header Or Cookie Too Large` with `client sent too long header line` in `proxy-error.log`; the nonce never reaches `app.log`. Because both clients stop at the same size, Chromium imposes no Bearer limit below nginx's. ML-DSA-44 fits with 4,812 bytes to spare; neither SLH-DSA parameter set fits at any size.

**Raised once: `large_client_header_buffers 4 512k`.** With nginx's line limit raised above the largest probe, the next layer is waitress, which rejects the request with `431 Request Header Fields Too Large` once its count of the request line and headers that nginx forwards reaches 262,144 bytes (`max_request_header_size`); `app.log` records `rejected by waitress: exceeds max_header of 262144`. Every configuration, including both SLH-DSA parameter sets, now verifies up to about 261.5 KB. The two clients' boundaries differ by 477 bytes because waitress counts the whole forwarded request, and nginx forwards the other headers each client sends: Chromium sends 501 more header bytes than http.client (`sec-ch-ua`, `user-agent`, `referer`, `accept-*`, and similar), of which 477 remain after nginx rewrites `Host` and drops `Connection`. At the last verified probe the application received the same 262,070 bytes of headers from both clients.

**Chromium sent request headers of 262,168 bytes** (its largest probe, rejected only by waitress) without an error, so no Chromium request header limit was found up to that size. A token that large cannot be verified directly at the application either, since the direct check goes through waitress too; every probe on the verified side of each boundary verified directly.

## Cookie and Bearer compared

| Transport | First limit at defaults (this machine) | Largest token | Configured limit and what it counts | Next limit |
| --- | --- | ---: | --- | --- |
| Cookie | nginx `proxy_buffer_size` (4 KiB) on the `Set-Cookie` response | 3,915 | 4,096 bytes of upstream response header block | Chromium: 4,096 bytes of cookie name + value (a 4,093-byte token) |
| Cookie, `--proxy-buffers 16k` | Chromium, cookie not stored | 4,093 | 4,096 bytes of name + value | nginx again at a 16,384-byte response header block |
| Bearer | nginx `large_client_header_buffers` (4 × 8k) on the request | 8,168 | 8,192 bytes of one header line, CRLF included | waitress: 262,144 bytes of forwarded request headers |
| Bearer, `--header-buffers 512k` | waitress, 431 | 261,519 (Chromium) / 261,996 (http.client) | 262,144 bytes of request line and headers | not reached: Chromium sent 262,168 bytes without error |

A Bearer header carries about twice the token a cookie does at the defaults (8,168 versus 3,915 bytes here, or 4,093 with the Mac's buffers), and its first two limits are both server settings that can be raised, while the cookie's binding limit on a 16 KiB-page system is Chromium's, which cannot. ML-DSA-44 tokens fit either transport with minimal claims; with the OIDC fixture (a 4,095-byte token) they are 2 bytes too large for a cookie, a margin small enough that a slightly different claim set fits (see [ML-DSA-44 claim headroom](#ml-dsa-44-claim-headroom)), but, by size, well within the Bearer limit (not probed with OIDC claims). SLH-DSA tokens fit neither at the defaults; as Bearer headers they fit once nginx's header buffers are raised past 10.6 KB (SHA2-128s) or 22.9 KB (SHA2-128f).

## ML-DSA-44 claim headroom

With typical OpenID Connect ID token claims ([fixtures/claims_oidc.json](fixtures/claims_oidc.json): 22 claims, 618 bytes of compact JSON) and production cookie attributes, the **unpadded ML-DSA-44 token is 4,095 bytes, so `jwt` + token is 4,098 bytes: 2 bytes over Chromium's 4,096-byte limit before any extra claim.** The headroom is negative at both buffer settings:

- **Pinned (16k), the Mac's defaults:** Chromium drops the cookie. The claims would have to shrink by at least 2 bytes of token to fit, and any additional claim breaks it again.
- **Default (WSL2):** nginx rejects first with 502, because the 4,156-byte `Set-Cookie` value makes a 4,297-byte response header block. From the boundary above, the token would have to be at most about 3,893 bytes (3,915 minus the 22 bytes the extra `Secure; ` and `; Max-Age=3600` attributes add); this figure is derived from the default-attribute boundary, not measured.

**The verdict turns on a few bytes of claims.** Removing 2 bytes from the 618-byte claim set gives a 4,093-byte token, exactly at Chromium's limit, and the pinned run stored a 4,093-byte ML-DSA-44 cookie; `"locale":"en"` instead of `"en-US"`, for example, saves 3 bytes (a 4,091-byte token). Adding any claim pushes it further over. So whether an ML-DSA-44 ID token fits a cookie on a 16 KiB-page system depends on the issuer's exact claims, and the result above holds for this fixture's values, which are illustrative rather than taken from a real issuer.

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
- **Bearer probes** (`client_request_headers` and `authorization_line` in `sweep.json`): `Authorization: Bearer <token>\r\n` is the line nginx's 8,192-byte buffer limits. For http.client, the request headers are computed from what it sends: the request line, `Host`, `Accept-Encoding: identity`, the `Authorization` line, and the final CRLF. At the default boundary they are 8,816 bytes from Chromium and 8,315 from http.client for an 8,168-byte token; the application received 8,719 and 8,242.
- Rejected probes show no request bytes because no cookie was sent; the next request carries only the page's ordinary headers (624 bytes as Chromium reported them).

## Reproduce

From a clean checkout with the environment from [TRANSPORT.md](TRANSPORT.md#setup):

```bash
python scripts/transport_stack.py sweep --output-dir results/transport/<run>/cookie-default
python scripts/transport_stack.py sweep --proxy-buffers 16k --output-dir results/transport/<run>/cookie-16k
python scripts/transport_stack.py sweep --alg ML-DSA-44 --claims oidc --attrs full --step 128 --max-bytes 6144 --output-dir results/transport/<run>/mldsa-oidc-default
python scripts/transport_stack.py sweep --alg ML-DSA-44 --claims oidc --attrs full --step 128 --max-bytes 6144 --proxy-buffers 16k --output-dir results/transport/<run>/mldsa-oidc-16k
python scripts/transport_stack.py sweep --transport bearer --output-dir results/transport/<run>/bearer-default
python scripts/transport_stack.py sweep --transport bearer --header-buffers 512k --step 16384 --max-bytes 327680 --output-dir results/transport/<run>/bearer-512k
```

or `make sweep` for the default and raised cookie and Bearer runs (the first, second, fifth, and sixth commands; not the two OIDC runs). The four cookie runs took about 5 minutes on the WSL2 machine; the Bearer runs took a few minutes each. Each run directory holds `sweep.json` (settings, every probe with its outcome, rejecting layer, evidence, nonces, and byte counts, and the boundaries), the four logs, gzip-compressed (`browser.log.gz`, `proxy-access.log.gz`, `proxy-error.log.gz`, `app.log.gz`; read them with `zcat`, and `sweep.json` lists each saved file under `evidence`), and the rendered `nginx.conf`, which marks every setting changed from the template with a `Not a default` comment. Every probe's issue and verify nonces can be found in each layer's log.

## Limitations

- **One machine.** These runs are from WSL2. The pinned run reproduces the Mac's nginx buffers, and the Mac's earlier `tokens` run agrees with it (the SLH-DSA-SHA2-128s cookie was dropped by Chromium there), but the sweep itself has not been run on macOS.
- **One browser, HTTP/1.1, no TLS.** Only Chromium was tested. HTTPS and HTTP/2, where header compression changes how nginx and Chromium apply their limits, are proposed for Sprint 3.
- **One limit raised.** Only nginx's request header buffers were raised (S2-05), and only once. waitress's 262,144-byte limit was not raised, so Chromium's own request header limit, if it has one above 262,168 bytes, is unmeasured.
- **One cookie.** Each probe sends a single `jwt` cookie. Real sites send other cookies alongside it, which count toward nginx's 8,192-byte `Cookie:` line and its total header buffers, but not toward Chromium's per-cookie limit. Cookie splitting is Sprint 3 work (S3-02).
- **Monotonic search.** Between coarse probes the sweep assumes the outcome changes only once; every boundary was confirmed by a probe on each side, and the exact-fill case was found because it is a different outcome.
- **Derived figure.** The 3,893-byte limit for OIDC claims with full attributes at WSL2's defaults is calculated from the measured default-attribute boundary, not probed.

## Questions for Sprint 3

1. **End to end (S3-01):** a Bearer-carried SLH-DSA token is 10.6–22.9 KB on every request. Once the header limits are raised, does that transfer cost more latency and throughput than the verification differences measured in Sprint 1?
2. **Smaller claims (S3-02):** how many OIDC claims must an ML-DSA-44 token drop to fit a cookie with production attributes, and what do those claims cost the application?
3. **Cookie splitting (S3-02):** at Chromium's 4,096-byte limit, an OIDC ML-DSA-44 token needs two cookies, an SLH-DSA-SHA2-128s token three, and an SLH-DSA-SHA2-128f token six. Do chunks stay within nginx's 8,192-byte `Cookie:` line and its total header buffers, and how does the application handle a missing or reordered chunk? Measured in [MITIGATION_RESULTS.md](MITIGATION_RESULTS.md#cookie-splitting).
4. **Reference tokens (S3-02):** since an SLH-DSA token cannot be carried in a cookie at any size, what does a server-side lookup add in latency, and what does it give up in stateless verification?
5. **HTTPS and HTTP/2 (S3-04):** do these boundaries hold over TLS, and how do HPACK header compression and HTTP/2's header-list limits move them?
6. **Other machines and servers:** do the boundaries reproduce on the Mac (and its 16 KiB nginx defaults), and in other browsers, proxies, or application servers?
