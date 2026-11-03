# Sprint 2 transport stack and documented limits

This document records the transport stack chosen in S2-01 and every layer's **documented** default limits for large cookies and headers. These limits come from documentation and source code and have not been measured yet; the sweeps in S2-04 and S2-05 measure them. Do not report anything here as a measured boundary.

## Stack

All layers run on `127.0.0.1` over plain HTTP/1.1 (no TLS, no HTTP/2), with every limit at its default. [scripts/transport_stack.py](scripts/transport_stack.py) starts the stack and checks it end to end; see the [README](README.md#check-the-transport-stack).

| Layer | Component | Version | Installed from | Why this one |
| --- | --- | --- | --- | --- |
| Browser | Chromium (Chrome for Testing), headless, driven by Playwright | Chromium 156.0.8078.4, Playwright 1.64.1 | pip, then `python -m playwright install chromium` | A real cookie store and network stack, scriptable from Python. Firefox and WebKit can be added through Playwright later. |
| Reverse proxy | nginx | 1.31.8 | conda-forge | The most common reverse proxy, with documented and configurable header buffers. Same version on macOS arm64 and Linux x86_64. |
| Application server | Gunicorn, sync worker, pure-Python HTTP parser | 26.2.0 | pip | Header limits are explicit, documented settings. Runs on macOS and Linux (WSL2). The faster C parser (`gunicorn[fast]`) is not installed. |
| Application | Flask on Werkzeug | Flask 3.1.3, Werkzeug 3.1.9 | pip | Small and familiar; the app is [scripts/transport_app.py](scripts/transport_app.py). |

Checked with `python scripts/transport_stack.py` on macOS 26.5.1 (Apple M5 Pro, Python 3.15.2), both in the existing environment and in a fresh one built from [environment.yml](environment.yml). **Not yet checked on WSL2.**

## Documented default limits

Sources are pinned to the listed versions where possible. "Source" means the limit was found in source code at that version's tag; "docs" means official documentation, which for nginx and Gunicorn is not versioned. Rows marked ✓ were also checked against the package installed here.

### Standards

| Spec | Limit | What it measures | When exceeded | Source |
| --- | --- | --- | --- | --- |
| [RFC 6265 §6.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-6.1) | User agents should support at least 4,096 bytes per cookie, 50 cookies per domain, 3,000 in total | Name, value, and attributes | The user agent may ignore the cookie entirely | docs |
| [RFC 6265bis draft-22](https://www.ietf.org/archive/id/draft-ietf-httpbis-rfc6265bis-22.html) (not yet an RFC) | 4,096 octets | Name + value | Cookie ignored entirely | docs |
| RFC 6265bis draft-22 | 1,024 octets | Each attribute value | That attribute ignored; cookie kept | docs |
| [RFC 9110 §5.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.4) | No predefined field or header-section limit | — | A server must respond with a 4xx status | docs |

### Chromium 156

Chromium documents none of these for users; all are from source at tag [`156.0.8078.4`](https://github.com/chromium/chromium/tree/156.0.8078.4/net).

| Constant | Default | What it measures | When exceeded |
| --- | --- | --- | --- |
| `ParsedCookie::kMaxCookieNamePlusValueSize` ([parsed_cookie.h](https://github.com/chromium/chromium/blob/156.0.8078.4/net/cookies/parsed_cookie.h)) | 4,096 bytes | Name + value, without the `=`; exactly 4,096 is accepted | **Cookie silently rejected**, whether set by `Set-Cookie` or `document.cookie`. Visible only in DevTools or through CDP (`blockedCookies`, reason `NameValuePairExceedsMaxSize`). |
| `ParsedCookie::kMaxCookieAttributeValueSize` | 1,024 bytes | Each attribute value | From `Set-Cookie`: that attribute dropped, cookie kept |
| Whole `Set-Cookie` line | No limit | — | — |
| `CookieMonster::kDomainMaxCookies` ([cookie_monster.h](https://github.com/chromium/chromium/blob/156.0.8078.4/net/cookies/cookie_monster.h)) | 180 per domain (purged to 150) | Cookie count per registrable domain | Silent eviction |
| `Cookie` request header | No size cap | All matching cookies joined with `"; "` into **one** header | — |
| Request headers for `fetch()` (such as `Authorization`) | **No cap found** ([http_stream_parser.cc](https://github.com/chromium/chromium/blob/156.0.8078.4/net/http/http_stream_parser.cc)) | — | — |

### nginx 1.31.8

Docs: [ngx_http_core_module](https://nginx.org/en/docs/http/ngx_http_core_module.html) and [ngx_http_proxy_module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html). Source: tag [`release-1.31.8`](https://github.com/nginx/nginx/tree/release-1.31.8/src/http).

| Directive | Default | What it measures | When exceeded |
| --- | --- | --- | --- |
| `client_header_buffer_size` | 1k | First buffer for the request line and headers; overflow moves to the large buffers | Not a rejection by itself |
| `large_client_header_buffers` (size) | 8k | **One whole header line** (name, value, CRLF) must fit in one buffer | **400 "Request Header Or Cookie Too Large"** (internally 494). Reason logged as "client sent too long header line" at **info** level only. |
| `large_client_header_buffers` (number) | 4 | Effectively the total header size, about 4 × 8 KB plus the first 1 KB; one line is never split across buffers | Same 400 |
| `max_headers` ✓ | 1,000 | Number of header lines | Same 400 |
| `proxy_buffer_size` | One memory page | The **response** headers from Gunicorn, including the app's `Set-Cookie` | Error log "upstream sent too big header"; client normally gets **502** |
| `underscores_in_headers` / `ignore_invalid_headers` | off / on | Header names containing `_` | Header silently dropped |

The memory page, and so the default `proxy_buffer_size`, is **16 KB on this Mac** (`getconf PAGESIZE` = 16384) and typically 4 KB on x86_64 Linux. Expect the response-cookie limit to differ between the two team machines.

### Gunicorn 26.2.0

Docs: [settings](https://gunicorn.org/reference/settings/). Source: tag [`26.2.0`](https://github.com/benoitc/gunicorn/tree/26.2.0/gunicorn/http).

| Setting | Default | What it measures | When exceeded |
| --- | --- | --- | --- |
| `limit_request_field_size` ✓ | 8,190 bytes | **Whole header line including the name**, plus 2 for CRLF. `Authorization: Bearer <jwt>` allows a JWT of at most 8,166 bytes. | **431 "Request Header Fields Too Large"**; logged as a warning, with no access-log line. A setting of `0` resets to 8,190 in this version, although the docs say it means unlimited. |
| `limit_request_fields` | 100 | Number of header fields | 431 |
| Total header buffer (derived) | 100 × (8,190 + 2) + 4 = 819,204 bytes | All header lines | 431 |
| `limit_request_line` | 4,094 bytes | Request line | 400; not relevant to these requests |
| `header_map` | `drop` | Header names containing `_` | Header silently dropped |

### Werkzeug 3.1.9 and Flask 3.1.3

| Item | Default | What it measures | When exceeded |
| --- | --- | --- | --- |
| Request header or cookie size | No limit ([sansio/http.py](https://github.com/pallets/werkzeug/blob/3.1.9/src/werkzeug/sansio/http.py)) | — | — |
| `Response.max_cookie_size` / Flask [`MAX_COOKIE_SIZE`](https://flask.palletsprojects.com/en/stable/config/#MAX_COOKIE_SIZE) ✓ | 4,093 bytes | The whole `Set-Cookie` value | **Python warning only**; the cookie is still sent, untruncated |

## What the documented limits predict

These are hypotheses for S2-04 and S2-05 to test, not results.

- **Cookies:** a token larger than 4,096 bytes minus the cookie name's length is dropped silently by Chromium and never reaches nginx; the app sees no cookie. ML-DSA-44's 3,355-byte token should fit, with 741 bytes of headroom minus the cookie name's length. Both SLH-DSA tokens should be dropped.
- **Split cookies (Sprint 3):** Chromium sends all cookies in one `Cookie` line, so splitting fails at nginx with a 400 once that line passes about 8 KB.
- **Bearer header:** a header line over about 8 KB gets nginx's 400. With nginx's limit raised, a line over 8,190 bytes gets Gunicorn's 431. ML-DSA-44 should pass; both SLH-DSA tokens should fail at nginx.
- **Issuing the cookie:** a `Set-Cookie` larger than `proxy_buffer_size` should make nginx return 502, at about 4 KB on WSL2 and 16 KB on this Mac.

## Notes for building the test environment (S2-02)

- nginx logs the reason for a 400 only at `info` level; the generated configuration already sets `error_log ... info`.
- Chromium's silent cookie drops are visible only through the DevTools Protocol, so the sweep should record `blockedCookies` from CDP `Network.responseReceivedExtraInfo` events.
- Playwright's `page.request` bypasses Chromium's network stack, so browser limits don't apply to it. Use page navigation or `fetch()` for browser measurements.
- Set cookies with the app's `Set-Cookie` response, as S2-04 specifies. Playwright's `context.add_cookies` takes a different code path in Chromium.
- Avoid underscores in custom header names; nginx and Gunicorn both drop them by default.

## Open questions for measurement

1. The exact boundaries: whether nginx's 8k counts the CRLF, whether Gunicorn rejects at 8,188 or 8,190 bytes of header line, and whether Chromium accepts exactly 4,096 bytes of name plus value.
2. In the gap between nginx's and Gunicorn's line limits, does nginx pass Gunicorn's 431 through unchanged?
3. nginx's real total header capacity with several large headers, since lines are not split across buffers.
4. The `Set-Cookie` size that triggers nginx's 502 on each machine.
5. Whether Chromium really sends a `fetch()` request with an `Authorization` header over 23 KB.

## How these limits were collected

A research pass read each component's documentation and its source at the listed tag. The Gunicorn header check and its 431 response, the Werkzeug cookie warning, nginx's acceptance of `max_headers`, and the page size were then checked against the packages and binary installed here (marked ✓). The Chromium limits come only from source and are the main thing S2-04 must confirm.
