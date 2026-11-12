# Transport stack: browser → reverse proxy → application

Sprint 2 sends tokens from a real browser through a reverse proxy to a Python application and finds where large tokens break (see [PROGRESS.md](PROGRESS.md#sprint-2-find-where-large-tokens-break-in-transport)). This document covers tasks S2-01 and S2-02: the chosen stack, each layer's version and documented default limits, setup on macOS and WSL2, a check that sends one request from the browser through the proxy to the application, and a token check that sends a normal-sized token from each of the six configurations through the same path as a cookie and as a Bearer header.

Every request in the check takes this path:

```text
Playwright for Python ──pipe──▶ Chromium (headless) ──HTTP/1.1──▶ nginx ──HTTP/1.1──▶ waitress ──WSGI──▶ scripts/transport_app.py
                                                     127.0.0.1:<proxy_port>      127.0.0.1:<app_port>
```

The machine-readable description of the stack is [transport/stack.json](transport/stack.json). [scripts/transport_stack.py](scripts/transport_stack.py) starts and checks the stack, [scripts/transport_tokens.py](scripts/transport_tokens.py) holds the token check, [scripts/transport_app.py](scripts/transport_app.py) is the application, and [transport/setup.sh](transport/setup.sh) creates the pinned environment.

## Stack

| Role | Component | Version | Installed from |
| --- | --- | --- | --- |
| Browser automation | Playwright for Python | 1.64.1 | PyPI wheel, pinned in [transport/requirements.txt](transport/requirements.txt) |
| Browser engine | Chromium (Chrome for Testing) | 156.0.8078.4 | Build pinned by the Playwright release, downloaded to Playwright's cache |
| Reverse proxy | nginx | 1.31.8 | conda-forge, pinned in [transport/conda-requirements.txt](transport/conda-requirements.txt) |
| Application server | waitress | 3.0.2 | PyPI wheel, pinned in [transport/requirements.txt](transport/requirements.txt) |

There is no application framework layer: [scripts/transport_app.py](scripts/transport_app.py) is a plain WSGI callable of about 300 lines, so nothing between waitress and the application parses or limits headers.

**Browser automation: Playwright for Python.** It has a Python API, so the stack stays in the language of Sprint 1. Each Playwright release pins one exact browser build for every platform, which makes the browser version reproducible. It drives Chromium over a pipe rather than a TCP port, so nothing else listens on the machine. `page.evaluate()` runs `fetch()` inside the page, so the check request really leaves through the browser, and `BrowserContext.cookies()` reads the browser's cookie jar for S2-04. *Alternative considered:* Selenium with ChromeDriver. It needs a separate WebDriver server listening on a TCP port and a driver that matches the browser; its version resolution happens at run time through Selenium Manager, which is harder to pin to one build on both machines.

**Browser engine: Chromium (Chrome for Testing).** Chromium is the most widely deployed engine, its cookie limit is a named constant in its source, and Playwright 1.64.1 pins the same build, 156.0.8078.4, for `mac-arm64` and `linux64`. The stack launches it with `channel="chromium"`, the full browser in new headless mode, which [Playwright describes as the real Chrome browser](https://playwright.dev/python/docs/browsers#chromium-new-headless-mode). *Alternatives considered:* Playwright's default headless shell, a separate lighter build that behaves differently in some cases; and Firefox or WebKit, which PROGRESS.md defers until one path works. Playwright's Firefox and WebKit builds are patched for automation, so they are further from the browsers people run.

**Reverse proxy: nginx.** nginx is a common reverse proxy in front of Python applications, and its request header buffers (`large_client_header_buffers 4 8k`) are a limit often reported when large cookies and JWTs fail. It is packaged on conda-forge for both osx-arm64 and linux-64 at the same version. *Alternatives considered:* Caddy, whose conda-forge package lags upstream (2.9.1 is the newest there), and whose header limits come from Go's `net/http` rather than from Caddy's own configuration; HAProxy, for which no conda-forge package was found.

**Application server: waitress.** waitress is a production WSGI server written in pure Python, so the same wheel installs on both platforms with no compiler or native HTTP parser. It runs in one process with threads, so stopping it is a single signal. It documents one request header limit, `max_request_header_size`, and passes header values to the application with only surrounding spaces and tabs removed, joining repeated headers with `", "`, which the echo needs to report what arrived. *Alternatives considered:* gunicorn 26.2.0, which documents an 8,190-byte `limit_request_field_size` but [joins repeated headers with a bare comma](https://github.com/benoitc/gunicorn/blob/26.2.0/gunicorn/http/wsgi.py#L228-L230) and runs pre-forked worker processes; uvicorn with h11, whose 16 KiB `max_incomplete_event_size` is [only checked while a request header is still incomplete](https://github.com/python-hyper/h11/blob/v0.16.0/h11/_connection.py#L481-L490), so a larger header that arrives in one read is accepted and the documented number is not a dependable bound.

### What the stack provides

- **Endpoints**, served by the application and reached through `proxy_url`: `GET /` returns the HTML test page ([transport/static/index.html](transport/static/index.html)); `GET /api/echo` returns a JSON echo of the request as the application received it; `GET /api/token/issue` and `GET /api/token/verify` issue and verify tokens (see [Token endpoints](#token-endpoints)); any other path, including other paths under `/api/`, returns a JSON 404 from the application.
- **Echo body:** `layer` (`"application"`), `method`, `path` (without the query string), `query` (each parameter's last value), and `headers` (each request header name in lowercase, mapped to its value as received; repeated headers are joined with `", "`).
- **Proxy marker:** nginx adds the response header `X-Transport-Proxy: nginx` to every response it forwards from the application, including 404s. Responses fetched directly from `app_url` do not have it. It is a response header, so it does not change the request bytes that later tasks measure.
- **Loopback only:** nginx and waitress listen only on `127.0.0.1`; Playwright talks to Chromium over a pipe.
- **Run directory:** the rendered nginx configuration, its pid and temporary directories, and the logs go under one run directory, a new directory under the system temporary directory by default. Nothing is written to the repository or to the conda environment, and the run directory is kept after the stack stops.
- **Logs:** one log per layer under `<run_dir>/logs`. Every request the checks send carries its own `nonce` query parameter, so one request can be followed through all of them.
  - `proxy-access.log`: one line per request nginx saw, with the request line, status, and `request_length`.
  - `proxy-error.log`: nginx's error log at `info` level, which includes rejections such as `client sent too long header line` and `upstream sent too big header`.
  - `app.log`: waitress messages and one line per request the application handled, with its target, status, and the sizes of the headers it received (see [Application log fields](#application-log-fields)). It also has one `rejected by waitress` line per request waitress rejected before the application ran, such as a 431 for an oversized header block, with its original request line and the bytes waitress had received.
  - `browser.log`: written by the `tokens` check, since Chromium keeps no request log of its own: the headers the browser sent and received and the contents of its cookie jar (see [Browser log](#browser-log)).

### Token endpoints

Both endpoints are in `route()` in [scripts/transport_app.py](scripts/transport_app.py), next to `/api/echo`, and sign and verify with the adapters in [scripts/algorithms.py](scripts/algorithms.py). `<name>` is one of the six `ADAPTERS` names: `RS256`, `ES256`, `EdDSA`, `ML-DSA-44`, `SLH-DSA-SHA2-128s`, or `SLH-DSA-SHA2-128f`.

- **Experiment keys:** the application holds one key pair per configuration, made with that adapter's `generate_keypair()` inside the application process the first time it is needed. A lock makes concurrent first requests share one pair, so a token issued on one waitress thread verifies on another. These are **ephemeral experiment keys, not production credentials**: they live only in memory, are never written to disk, logged, or returned in a response, and disappear when the process stops. Each application process makes its own keys, so a token from another stack, or one signed with any other key, gets 401. Every JSON response from both endpoints, errors included, has `"experiment_key": true`.
- **`GET /api/token/issue?alg=<name>`** (or with `&delivery=cookie`) signs [fixtures/claims.json](fixtures/claims.json), unchanged and unpadded, and answers 200 with exactly one `Set-Cookie: jwt=<token>; Path=/; HttpOnly; SameSite=Strict` header. The application adds no other header besides `Content-Type` and `Content-Length`. The body is `{"layer": "application", "algorithm": <name>, "delivery": "cookie", "cookie_name": "jwt", "token_bytes": <n>, "set_cookie_bytes": <n>, "experiment_key": true}`. The token is left out of the body so the response stays small: ML-DSA-44's `Set-Cookie` value is 3,394 bytes and has to fit, with the other response headers, in nginx's `proxy_buffer_size`, which is 4 KiB on x86_64 Linux.
- **`GET /api/token/issue?alg=<name>&delivery=body`** answers 200 with no `Set-Cookie` and the body `{"layer": "application", "algorithm": <name>, "delivery": "body", "token": <token>, "token_bytes": <n>, "experiment_key": true}`. The Bearer check gets its token this way, so it never depends on a `Set-Cookie` response.
- **Issue errors:** a missing `alg`, an `alg` outside the six names, or a `delivery` other than `cookie` or `body` gets 400 with no `Set-Cookie` and `{"layer": "application", "error": <reason>, "algorithms": [the six names], "experiment_key": true}`. Other query parameters, such as `nonce`, are ignored.
- **Cookie name and attributes:** `jwt`, with exactly `Path=/; HttpOnly; SameSite=Strict`. There is no `Secure`, `Max-Age`, or `Expires`: the stack is plain HTTP on `127.0.0.1` (see [Limitations](#limitations)), and S2-04 varies the attributes.
- **`GET /api/token/verify`** looks for a token in two places: a cookie named exactly `jwt` (the `Cookie` header is split on `;`, each pair is stripped of whitespace and split at its first `=`, and other cookies are ignored), and an `Authorization` header whose scheme is `Bearer` in any letter case (the token is the rest of the value after the scheme and its whitespace; other schemes are ignored). With exactly one token, the application picks the adapter named by the token's unverified JOSE header `alg`, which must be one of the six names, and calls that adapter's `verify_token` with its experiment public key.
- **Verify responses:** 200 with `{"layer": "application", "verified": true, "algorithm": <name>, "source": "cookie" | "bearer", "token_bytes": <n>, "claims": {...}, "experiment_key": true, "received": {...}}`, where `claims` equals the fixture for an issued token. 401 when there is no token or verification fails for any reason: a changed payload or signature, a key from another process, an `alg` of `none`, `HS256`, or any name outside the six, a malformed segment, a header that is not JSON, or an expired `exp`. 400 when there is more than one token: a `jwt` cookie and a Bearer header, or two `jwt` cookies. Both error bodies are `{"layer": "application", "verified": false, "source": <the source used, or null>, "error": <reason>, "experiment_key": true, "received": {...}}`. Malformed input never produces a 500.
- **`received`:** `headers` (the number of headers), `header_bytes` (the sum over headers of `len(name) + len(value) + 4`, the size of `name: value\r\n`), `cookie_bytes`, and `authorization_bytes` (the length of that header's value, or `null` when it is absent). They are computed from the same headers `/api/echo` reports, so names are lowercased, values are stripped by waitress, repeated headers are joined, and `Host` is nginx's rewrite. They are not raw wire bytes; exact byte accounting is S2-03 work.

### Application log fields

Each request the application handles, on any path, writes one INFO line to `app.log`: the S2-01 prefix `<remote_addr> "<METHOD> <target> <protocol>" <status>`, then `headers=<n> header_bytes=<n> cookie_bytes=<n|-> authorization_bytes=<n|->` with the `received` values above (`-` for null). Lines for the token endpoints add `alg=<name|-> token_bytes=<n|->`, and verify lines add `verified=true|false`. The log never contains header values or tokens; the target with its query string is logged. A line from the run in [The token check](#the-token-check):

```text
2026-11-10 16:42:57,281 transport_app INFO 127.0.0.1 "GET /api/token/verify?nonce=e7da9cf156cd39162fa24bcb612866ba HTTP/1.1" 200 headers=15 header_bytes=3912 cookie_bytes=3359 authorization_bytes=- alg=ML-DSA-44 token_bytes=3355 verified=true
```

The `rejected by waitress` line keeps its S2-01 text and appends `received_bytes=<n>`, the number of request bytes waitress had taken in for that request when it rejected it. A trial run on this Mac that sent a 300,000-byte header directly to the application logged `"GET /api/token/verify?nonce=431431431431 HTTP/1.1" 431 rejected by waitress: exceeds max_header of 262144 received_bytes=262144`.

### Browser log

Chromium keeps no request log that the check could read, so the `tokens` check writes `<run_dir>/logs/browser.log` from the Playwright side. It is UTF-8 JSON Lines, appended by every run, one object per line, each with `event`, `algorithm`, and `transport`:

- **`request`:** `url`, `method`, and `headers` from Playwright's `Request.all_headers()` (lowercase names), for every request the page makes: the page load, the issue, and the verify. These are the `cookie` and `authorization` headers the browser actually sent.
- **`response`:** `url`, `status`, and `headers` from `Response.all_headers()`, which include `set-cookie`; `fetch()` hides that header from the page.
- **`request_failed`:** `url` and Playwright's `failure` text, for a request that got no response.
- **`cookies`:** `step` (`after_issue` or `after_verify`) and `cookies`, the context's cookie jar from `BrowserContext.cookies()` (name, value, domain, path, expires, httpOnly, secure, sameSite).

Unlike `app.log`, `browser.log` holds full header values and tokens. They are signed with experiment keys that are discarded when the stack stops.

### Configuration that is not a default

No header-, cookie-, line-, or buffer-size setting is changed in [transport/nginx.conf.template](transport/nginx.conf.template) or in [scripts/transport_app.py](scripts/transport_app.py). For nginx that covers `client_header_buffer_size` (1k), `large_client_header_buffers` (4 8k), `proxy_buffer_size` and `proxy_buffers` (one memory page, eight pages), `proxy_busy_buffers_size`, `client_body_buffer_size`, `underscores_in_headers` (off), and `ignore_invalid_headers` (on). For waitress it covers `max_request_header_size` (262,144), `max_request_body_size`, `recv_bytes`, `send_bytes`, `inbuf_overflow`, and `outbuf_overflow`.

The settings that are changed:

- nginx: `daemon off`, the pid, lock, log, and temporary paths (all under the run directory), `error_log ... info`, a `log_format` that adds `$request_length` and `$upstream_status`, `listen 127.0.0.1:<proxy_port>`, `proxy_pass http://127.0.0.1:<app_port>`, and `add_header X-Transport-Proxy "nginx" always`.
- nginx: `timer_resolution 100ms`. On this Mac, the conda-forge osx-arm64 build fails every `kevent()` call with `EINVAL` (error 22) in a busy loop while a browser keeps a keep-alive connection open, writing hundreds of thousands of log lines per second. The [kqueue module](https://github.com/nginx/nginx/blob/release-1.31.8/src/event/modules/ngx_kqueue_module.c#L529-L537) shifts `tv_nsec` left 32 bits when the build defines `NGX_DARWIN_KEVENT_BUG`, which makes any timeout with a millisecond part invalid; that build flag appears to be set in this package. With a timer resolution, nginx calls `kevent()` without a timeout, and the loop no longer occurs. The directive does not affect header handling and is harmless on Linux, so both platforms use the same configuration.
- waitress: `host="127.0.0.1"`, the port, and `clear_untrusted_proxy_headers=False`, so that `Forwarded` and `X-Forwarded-*` headers sent by a client reach the application and appear in the echo instead of being removed.
- waitress: `LoggingParser` in [scripts/transport_app.py](scripts/transport_app.py) subclasses waitress's own request parser only to keep the original request line. When waitress rejects a request (for example with 431), it replaces the target with `/` before the application could log it, so the subclass writes the rejected request line, the status, and the bytes received to `app.log`. Parsing and every limit are still waitress's own.
- Test page: [transport/static/index.html](transport/static/index.html) declares an empty icon (`<link rel="icon" href="data:,">`), so Chromium does not request `/favicon.ico`, a request without a nonce that would otherwise appear as a 404 in `proxy-access.log` and `app.log`.

Defaults that rewrite request headers are left as they are. nginx 1.31.8 speaks [HTTP/1.1 to the application](https://github.com/nginx/nginx/blob/release-1.31.8/src/http/modules/ngx_http_proxy_module.c#L4068-L4069), sets `Host` to `127.0.0.1:<app_port>` (`$proxy_host`), and does not forward `Connection`, `Keep-Alive`, `TE`, `Expect`, `Upgrade`, or `Proxy-Connection` ([proxy module defaults](https://github.com/nginx/nginx/blob/release-1.31.8/src/http/modules/ngx_http_proxy_module.c#L761-L772)). nginx and waitress both drop request headers whose names contain `_`. The echo therefore shows the headers the application received, which are not byte-for-byte the headers the browser sent.

## Versions and documented limits

These values are **documented defaults, not measured boundaries**. Each comes from the component's official documentation or from its source code at the pinned release tag; S2-04 and S2-05 measure the real boundaries. "None" means that the layer documents no numeric limit of that kind; the note for each layer says what bounds it instead.

| Layer | Component | Version | Cookie size | Single header size | Total request header size | Sources |
| --- | --- | --- | --- | --- | --- | --- |
| Browser automation | Playwright for Python | 1.64.1 | None of its own: cookies live in the browser's jar | None of its own: the browser sends the requests | None of its own | [add_cookies](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-add-cookies), [launch](https://playwright.dev/python/docs/api/class-browsertype#browser-type-launch), [evaluate](https://playwright.dev/python/docs/api/class-page#page-evaluate), [APIRequestContext](https://playwright.dev/python/docs/api/class-apirequestcontext) |
| Browser engine | Chromium (Chrome for Testing) | 156.0.8078.4 | 4,096 bytes of name + value per cookie | None documented | None documented | [parsed_cookie.h](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.4/net/cookies/parsed_cookie.h), [parsed_cookie.cc](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.4/net/cookies/parsed_cookie.cc), [http_stream_parser.cc](https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.4/net/http/http_stream_parser.cc), [Fetch](https://fetch.spec.whatwg.org/), [RFC 6265, section 6.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-6.1) |
| Reverse proxy | nginx | 1.31.8 | None cookie-specific: the whole `Cookie` line is one header field | 8,192 bytes per header line | 32,768 bytes (4 buffers × 8k, approximate) | [large_client_header_buffers](https://nginx.org/en/docs/http/ngx_http_core_module.html#large_client_header_buffers), [client_header_buffer_size](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_header_buffer_size), [proxy_buffer_size](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffer_size), [core module source](https://github.com/nginx/nginx/blob/release-1.31.8/src/http/ngx_http_core_module.c#L3628-L3632), [request source](https://github.com/nginx/nginx/blob/release-1.31.8/src/http/ngx_http_request.c#L1657-L1700), [proxy module source](https://github.com/nginx/nginx/blob/release-1.31.8/src/http/modules/ngx_http_proxy_module.c#L3743-L3745) |
| Application server | waitress | 3.0.2 | None cookie-specific: counts toward the total | None per header: counts toward the total | 262,144 bytes | [arguments](https://docs.pylonsproject.org/projects/waitress/en/v3.0.2/arguments.html), [adjustments.py](https://github.com/Pylons/waitress/blob/v3.0.2/src/waitress/adjustments.py#L242-L243), [parser.py (limit)](https://github.com/Pylons/waitress/blob/v3.0.2/src/waitress/parser.py#L81-L123), [parser.py (headers)](https://github.com/Pylons/waitress/blob/v3.0.2/src/waitress/parser.py#L228-L246) |

### What each limit counts

- **Playwright for Python** adds no HTTP layer to the requests the check makes: they come from `fetch()` inside the page, and cookies set by the page or by `BrowserContext.add_cookies()` are stored and sent by Chromium. Playwright's own `APIRequestContext` client bypasses the browser and is not used.
- **Chromium cookie (4,096 bytes):** the bytes of one cookie's name plus its value (`kMaxCookieNamePlusValueSize`); the `=` and the attributes are not counted. A `Set-Cookie` header or `document.cookie` string over the limit is rejected and not stored (`EXCLUDE_NAME_VALUE_PAIR_EXCEEDS_MAX_SIZE`), which S2-04 counts as a browser rejection. Each attribute value, such as `Path` or `Domain`, has a separate 1,024-byte limit (`kMaxCookieAttributeValueSize`). [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.html#section-6.1) asks browsers to support at least 4,096 bytes per cookie, counting name, value, and attributes.
- **Chromium request headers (none documented):** Chromium's HTTP/1.1 stream parser joins the request line and headers and sends them without a size check, and the [Fetch standard](https://fetch.spec.whatwg.org/) sets no header size limit. The total `Cookie` header Chromium builds is bounded only indirectly, by the per-cookie limit and the number of cookies it keeps per domain.
- **nginx single header (8,192 bytes):** one request header line, from the start of the field name to the end of its line, must fit in one `large_client_header_buffers` buffer (8k by default). A longer line gets `400 Request Header Or Cookie Too Large`; a request line that is too long gets 414. Lines that fit in the first 1k `client_header_buffer_size` buffer never need a large buffer. The `Cookie` header is one such line, so all cookies sent together share this limit; nginx has no separate cookie limit.
- **nginx total (32,768 bytes, approximate):** once the 1k buffer is full, the request line and header lines are read into at most four 8k large buffers. A line never spans two buffers and lines already parsed stay in the first buffer, so the usable total depends on how the lines fall into buffers. Running out of buffers also gets 400.
- **nginx response headers:** `Set-Cookie` headers from the application must fit, with the status line and every other response header, in `proxy_buffer_size`, which defaults to one memory page. The documentation says 4K or 8K depending on the platform; the [source](https://github.com/nginx/nginx/blob/release-1.31.8/src/http/modules/ngx_http_proxy_module.c#L3743-L3745) uses `ngx_pagesize`, which is 4 KiB on x86_64 Linux and 16 KiB on Apple Silicon macOS. An upstream header that does not fit gets `502` and `upstream sent too big header` in the error log. This is the one default that differs between the two machines, and it matters for S2-04's `Set-Cookie` sweep.
- **waitress total (262,144 bytes):** the bytes of the request line and all header lines, including every CRLF and the blank line that ends the header block. A request is rejected with `431 Request Header Fields Too Large` once that count reaches 262,144, so 262,143 bytes is the largest accepted header block. waitress has no per-header or cookie limit; both count toward this total.

### Settings that change each limit

| Layer | Limit | Setting | Where to change it |
| --- | --- | --- | --- |
| Chromium | Cookie name + value | None: compile-time constant | — |
| nginx | Single header line and total | `large_client_header_buffers 4 8k` (number and size of buffers) | `http` or `server` block of [transport/nginx.conf.template](transport/nginx.conf.template) |
| nginx | First header buffer | `client_header_buffer_size 1k` | `http` or `server` block of the template |
| nginx | Upstream response headers, including `Set-Cookie` | `proxy_buffer_size` (one memory page) | `location` block of the template |
| waitress | Total request header | `max_request_header_size=262144` | the `waitress.serve(...)` call in [scripts/transport_app.py](scripts/transport_app.py) |

## Setup

Setup needs only a conda installation (for example [Miniforge](https://conda-forge.org/download/)); there is no Docker, Homebrew, sudo, or user-level pip. [transport/setup.sh](transport/setup.sh) takes the environment prefix as its only argument and can be run again to update an existing environment. It uses `$CONDA_EXE` if set, otherwise `conda` on `PATH`, and it:

1. creates or updates the environment at `PREFIX` from conda-forge only (`--override-channels -c conda-forge`) with the exact pins in [transport/conda-requirements.txt](transport/conda-requirements.txt): Python 3.15.2 (the standard `cp315` build), pip 26.2.2, and nginx 1.31.8;
2. installs the Sprint 1 packages from [requirements.txt](requirements.txt) and the transport packages from [transport/requirements.txt](transport/requirements.txt), all pinned with `==`, with `PREFIX`'s own pip and with user site-packages disabled;
3. runs `python -m playwright install --no-shell --no-remove chromium`, which downloads the Chrome for Testing build pinned by Playwright 1.64.1 to Playwright's default cache (`~/Library/Caches/ms-playwright` on macOS, `~/.cache/ms-playwright` on Linux), without removing builds other installations use;
4. finishes with `PREFIX/bin/python scripts/transport_stack.py versions` and exits with its status, so a successful setup means every installed version matches [transport/stack.json](transport/stack.json).

It stops at the first failing step. The environment does not need to be activated: every command below calls `PREFIX/bin/python` directly. Run the commands from the repository root.

### macOS (Apple Silicon)

```bash
export TRANSPORT_ENV="$HOME/miniforge3/envs/cis628-transport"
CONDA_EXE="$HOME/miniforge3/bin/conda" bash transport/setup.sh "$TRANSPORT_ENV"
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py check
```

No other prerequisite was needed on macOS 26.5.1.

### WSL2 (x86_64 Linux)

```bash
export TRANSPORT_ENV="$HOME/miniconda3/envs/crypto"
CONDA_EXE="$HOME/miniconda3/bin/conda" bash transport/setup.sh "$TRANSPORT_ENV"
# Only if setup.sh ended with "browser (... installed not found)", run by you
# (setup.sh never uses sudo): Chromium's system libraries.
sudo "$TRANSPORT_ENV/bin/python" -m playwright install-deps chromium
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py versions
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py check
```

Any conda installation works; point `CONDA_EXE` at its `conda` and `PREFIX` at the environment. On the WSL2 machine the stack was installed into the existing Sprint 1 `crypto` environment of a Miniconda installation. Because setup installs only from conda-forge, that replaced the environment's Python 3.15.2 build from Anaconda's default channel with conda-forge's (`python-3.15.2-h6e52b48_100_cp315`) and updated openssl, libgcc, libstdcxx, libffi, and a few other libraries; the Sprint 1 benchmark run on that machine (`20261103T181323053798Z`) used the earlier build.

If Chromium's shared libraries are missing, as on a minimal WSL2 distribution, the first `setup.sh` run ends with `Error: version mismatch: browser (documented 156.0.8078.4, installed not found)` after everything else is installed. [`playwright install-deps`](https://playwright.dev/python/docs/browsers#install-system-dependencies) installs those libraries with `apt-get`; after it, `versions` should exit 0, and running `setup.sh` again is safe. On the tested Ubuntu 24.04.4 distribution the libraries were already present, so `install-deps` was not needed and `setup.sh` exited 0 on its first run. The Sprint 1 `pqcrypto` wheel for Linux requires glibc 2.34 or later (Ubuntu 22.04 or newer).

### Cross-platform pins

The same versions are used on both platforms; only conda build strings and wheel platform tags differ. Availability for linux-64 was checked from this Mac, outside the repository:

- `CONDA_OVERRIDE_GLIBC=2.35 conda create --dry-run --platform linux-64 --override-channels -c conda-forge --file transport/conda-requirements.txt` solves to `python-3.15.2-h6e52b48_100_cp315`, `pip-26.2.2`, and `nginx-1.31.8-h1ababa1_0` (osx-arm64 uses `python-3.15.2-h2e4dbab_100_cp315` and `nginx-1.31.8-hcc312dc_0`).
- `pip download --only-binary=:all: --no-deps --python-version 3.15 --implementation cp --abi cp315 --abi abi3 --abi none` with manylinux x86_64 platform tags found a wheel for every pin in [requirements.txt](requirements.txt) and [transport/requirements.txt](transport/requirements.txt), for example `playwright-1.64.1-py3-none-manylinux1_x86_64.whl` and `greenlet-3.5.6-cp315-cp315-manylinux_2_24_x86_64.manylinux_2_28_x86_64.whl`.
- `PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu22.04-x64 python -m playwright install --dry-run --no-shell chromium` reports the same Chrome for Testing 156.0.8078.4 (playwright chromium v1248), downloaded from the `linux64` build directory.

## Run the check

```bash
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py check
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py check --proxy-port 8080 --app-port 8081 --run-dir /tmp/transport-run --timeout 30
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py tokens
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py tokens --alg ML-DSA-44 --alg SLH-DSA-SHA2-128s --timeout 30
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py serve
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py versions
"$TRANSPORT_ENV/bin/python" -m unittest discover -s tests -v
```

- **`check`** starts waitress and nginx, waits until `GET <proxy_url>/api/echo` returns the echo, launches headless Chromium, loads `<proxy_url>/`, and from that page sends `fetch("<proxy_url>/api/echo?nonce=<random hex>")`. It fails unless the page and the echo return 200, the echo response carries `X-Transport-Proxy`, the echoed nonce matches, the `User-Agent` the application received equals the page's `navigator.userAgent`, and Chromium reports the manifest version. It then closes the browser, stops both servers, prints one JSON object, and exits 0. On failure it prints a message starting with `Error:` to stderr and exits 1, with every process it started stopped. Ports default to free ones, the run directory to a new temporary directory, and the timeout (for startup and for each browser step) to 60 seconds.
- **`tokens`** takes the same options plus `--alg NAME`, which can be repeated and accepts the six `ADAPTERS` names (default: all six, in `ADAPTER_LIST` order). It starts the stack, sends each configuration's fixture token from the browser through nginx to the application as a cookie and as a Bearer header (see [The token check](#the-token-check)), stops the stack, and prints the result as JSON on stdout, with a one-line summary per pair on stderr. It exits 0 when every pair matches what the documented default limits predict. When the check ran but a pair did not match, it still prints the JSON, writes a line starting with `Error:` that names those pairs, and exits 1. Startup or browser failures print `Error: ...` and exit 1; usage errors, including an unknown or repeated `--alg`, exit 2.
- **`serve`** takes the same options, starts the stack, prints one line with `proxy_url`, `app_url`, and `run_dir`, and runs until SIGINT (Ctrl+C) or SIGTERM.
- **`versions`** prints the documented and installed version of every layer and exits 1 if any differs or is missing.
- The full test suite needs the transport environment; set `TRANSPORT_ENV` as in [Setup](#setup).

The same functions are available from Python as `scripts.transport_stack`: `start_stack(proxy_port=None, app_port=None, run_dir=None, timeout=60.0)` is a context manager that yields an object with `proxy_url`, `app_url`, and `run_dir`; `run_check(stack, timeout=60.0)` returns the result below; `run_token_check(stack, algorithms=None, timeout=60.0)` returns the token check result described in [The token check](#the-token-check); `installed_versions()` and `load_manifest()` return the installed and documented versions.

Output of `check` from a real run on the Apple Silicon machine:

```json
{
  "ok": true,
  "proxy_url": "http://127.0.0.1:51437",
  "app_url": "http://127.0.0.1:51438",
  "run_dir": "/var/folders/jp/6z_3s2b96kgdyxxg83f56cwh0000gn/T/transport-stack-2y_i0r4d",
  "layers": [
    {
      "role": "automation",
      "component": "Playwright for Python",
      "version": "1.64.1"
    },
    {
      "role": "browser",
      "component": "Chromium (Chrome for Testing)",
      "version": "156.0.8078.4"
    },
    {
      "role": "proxy",
      "component": "nginx",
      "version": "1.31.8"
    },
    {
      "role": "app_server",
      "component": "waitress",
      "version": "3.0.2"
    }
  ],
  "browser": {
    "version": "156.0.8078.4",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36"
  },
  "page": {
    "url": "http://127.0.0.1:51437/",
    "status": 200
  },
  "request": {
    "url": "http://127.0.0.1:51437/api/echo?nonce=a7e9c08d158d5ecc90a419a859c90cc2",
    "nonce": "a7e9c08d158d5ecc90a419a859c90cc2"
  },
  "response": {
    "status": 200,
    "headers": {
      "connection": "keep-alive",
      "content-length": "782",
      "content-type": "application/json",
      "date": "Wed, 04 Nov 2026 09:45:47 GMT",
      "server": "nginx/1.31.8",
      "x-transport-proxy": "nginx"
    },
    "body": {
      "layer": "application",
      "method": "GET",
      "path": "/api/echo",
      "query": {
        "nonce": "a7e9c08d158d5ecc90a419a859c90cc2"
      },
      "headers": {
        "host": "127.0.0.1:51438",
        "pragma": "no-cache",
        "cache-control": "no-cache",
        "sec-ch-ua-platform": "\"macOS\"",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36",
        "sec-ch-ua": "\"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"156\"",
        "sec-ch-ua-mobile": "?0",
        "accept": "*/*",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "referer": "http://127.0.0.1:51437/",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9"
      }
    }
  }
}
```

`response.headers` are the headers the browser saw; `response.body.headers` are the headers the application received. The `host` value shows nginx's rewrite to the application's address.

### The token check

`run_token_check` (and the `tokens` command) sends a normal-sized token, signed over the unpadded Sprint 1 fixture, for each configuration: 464 bytes for RS256, 208 for ES256 and EdDSA, 3,355 for ML-DSA-44, 10,613 for SLH-DSA-SHA2-128s, and 22,922 for SLH-DSA-SHA2-128f, the sizes in [RESULTS.md](RESULTS.md). Every request carries a fresh 32-hex-digit `nonce`. One headless Chromium is launched, with the same channel as `check`, and every (configuration, transport) pair gets a new `BrowserContext`, so no cookie carries over. For each pair, cookie first and then Bearer:

1. **Direct issue:** a non-browser client (`http_get`) fetches `<app_url>/api/token/issue?alg=<name>&delivery=body&nonce=<hex>`. The token's length is the pair's `token_bytes`.
2. **Page:** the new context loads `<proxy_url>/?nonce=<hex>` through nginx.
3. **Cookie pair:** the page calls `fetch()` on the issue URL with `delivery=cookie`, the check reads the cookie jar with `BrowserContext.cookies()`, the page calls `fetch()` on `<proxy_url>/api/token/verify?nonce=<hex>` with default credentials so the browser sends its own `jwt` cookie, and the check reads the jar again. The check never adds the cookie itself.
4. **Bearer pair:** the page calls `fetch()` on the issue URL with `delivery=body`, then on the verify URL with the header `Authorization: Bearer <token>`.
5. **Direct verify:** the directly issued token goes to `<app_url>/api/token/verify?nonce=<hex>` with the non-browser client, as `Cookie: jwt=<token>` or `Authorization: Bearer <token>`. This shows whether the configuration verifies at the application at all, without the browser or nginx.

Every browser request is sent by `fetch()` from the page loaded through the proxy, never through Playwright's `APIRequestContext`. After the last pair, the check waits up to 5 seconds for nginx to log every request that got a response (nginx writes its access log line when the response finishes), then looks for each request's nonce in `browser.log`, `proxy-access.log`, `proxy-error.log`, and `app.log`. The browser is closed before the function returns, and the stack keeps running.

**Outcome.** A pair is `verified` only when the page returned 200; the issue returned 200 (and, for a cookie pair, the jar then holds a `jwt` cookie); the verify returned 200 with the `X-Transport-Proxy` header and a body with `verified: true`, the pair's `algorithm`, and the pair's transport as `source`; the application received a `Cookie` of 4 + `token_bytes` bytes (`jwt=` and the token) or an `Authorization` of 7 + `token_bytes` bytes (`Bearer ` and the token), and not the other header; and the issue and verify nonces are in `browser.log`, `proxy-access.log`, and `app.log`. Otherwise it is `rejected`.

**Rejecting layer.** For a rejected pair, `rejected_by` names the first layer along browser → proxy → app_server → application that did not pass the first failed step on, taking the issue request, then (for a cookie pair) the cookie jar, then the verify request:

- **`browser`:** the issue returned 200 with a `Set-Cookie` (per `browser.log`) but the jar has no `jwt` cookie afterwards, or a request's nonce never reached `proxy-access.log`.
- **`proxy`:** the browser got 400 or more, or no response, for a nonce that is in `proxy-access.log`, and either the nonce is not in `app.log` (nginx rejected the request, such as 400 for a header line that is too long) or `app.log` shows that the application answered 200 (nginx rejected the response, such as 502 `upstream sent too big header`).
- **`app_server`:** `app.log` has a `rejected by waitress` line with the nonce.
- **`application`:** the application itself answered with an error status, such as 401.

`rejected_by` is null when the pair verified or no layer can be identified. `evidence` names the layer and quotes the observation or log lines, with token-like runs shortened to `[...]`, in at most 1,000 characters.

**Expected outcome.** `expected` comes from the documented defaults in [transport/stack.json](transport/stack.json), read at run time (a null `bytes` means no limit). A cookie pair is expected to verify only when `len("jwt") + token_bytes` is at most the browser's cookie limit (4,096) and `len("Cookie: jwt=") + token_bytes` is at most nginx's single header limit (8,192). A Bearer pair is expected to verify only when `len("Authorization: Bearer ") + token_bytes` is at most 8,192. These predictions are coarse, the fixture tokens are far from every boundary, and they never cause a request to be skipped: every pair is attempted.

**SLH-DSA at the default limits.** Both SLH-DSA fixture tokens (10,613 and 22,922 bytes) are larger than Chromium's 4,096-byte cookie limit and nginx's 8,192-byte header line, so they cannot cross browser → proxy with the defaults, and their four pairs are expected to be rejected. As a Bearer header, nginx answers 400 and logs `client sent too long header line`. As a cookie, the `Set-Cookie` response must first fit in nginx's `proxy_buffer_size`: on this Mac (16 KiB) the 10,652-byte SLH-DSA-SHA2-128s `Set-Cookie` passes nginx and Chromium silently drops the cookie, so the browser rejects it; the 22,961-byte SLH-DSA-SHA2-128f `Set-Cookie` gets 502 `upstream sent too big header` from nginx. On x86_64 Linux, where `proxy_buffer_size` is 4 KiB, the SLH-DSA-SHA2-128s cookie fails at nginx with 502 instead, and ML-DSA-44's 3,394-byte `Set-Cookie` (about 3.5 KB of response headers) still fits; both were confirmed by the WSL2 run below. All four pairs still verify when the token is sent directly to the application. No limit is raised and no cookie is split for S2-02: those are S2-05 and S3-02 work.

**Result.** `run_token_check` returns, and `tokens` prints, a JSON object with `ok` (true when every pair is `ok` and Chromium reports the manifest's browser version), `proxy_url`, `app_url`, `run_dir`, `layers` (as in `check`), `browser` (`version`, `user_agent`), `algorithms` (the names run, in order), `logs` (absolute paths of `browser.log`, `proxy-access.log`, `proxy-error.log`, and `app.log` as `browser`, `proxy_access`, `proxy_error`, and `app`), and `results`: one entry per configuration and transport, cookie then Bearer. Each entry has `algorithm`, `transport`, `token_bytes`, `expected`, `outcome`, `rejected_by`, `ok` (the outcome matches `expected`, a rejected pair names a layer, and the direct check verified), `page_status`, `cookie_stored` (null for Bearer), `evidence`, `issue` (`url`, `nonce`, `status`, `logs`), `verify` (`url`, `nonce`, `status`, `body`, the parsed application JSON or null, and `logs`), and `direct` (`url`, `nonce`, `status`, `verified`). Each `logs` object says, per log file, whether a line contains that request's nonce.

Output of `tokens` from a real run on the Apple Silicon machine (Apple M5 Pro, macOS 26.5.1) on November 10, 2026. The per-pair summary on stderr:

```text
RS256              cookie     464 bytes  verified                  expected verified  direct verified
RS256              bearer     464 bytes  verified                  expected verified  direct verified
ES256              cookie     208 bytes  verified                  expected verified  direct verified
ES256              bearer     208 bytes  verified                  expected verified  direct verified
EdDSA              cookie     208 bytes  verified                  expected verified  direct verified
EdDSA              bearer     208 bytes  verified                  expected verified  direct verified
ML-DSA-44          cookie   3,355 bytes  verified                  expected verified  direct verified
ML-DSA-44          bearer   3,355 bytes  verified                  expected verified  direct verified
SLH-DSA-SHA2-128s  cookie  10,613 bytes  rejected by browser       expected rejected  direct verified
SLH-DSA-SHA2-128s  bearer  10,613 bytes  rejected by proxy         expected rejected  direct verified
SLH-DSA-SHA2-128f  cookie  22,922 bytes  rejected by proxy         expected rejected  direct verified
SLH-DSA-SHA2-128f  bearer  22,922 bytes  rejected by proxy         expected rejected  direct verified
```

The same check on the WSL2 machine (Ubuntu 24.04.4, x86_64) on November 12, 2026. Only the SLH-DSA-SHA2-128s cookie differs: nginx rejected its `Set-Cookie` response with 502 and logged `upstream sent too big header`, while the application had answered 200, because `proxy_buffer_size` is 4 KiB there.

```text
RS256              cookie     464 bytes  verified                  expected verified  direct verified
RS256              bearer     464 bytes  verified                  expected verified  direct verified
ES256              cookie     208 bytes  verified                  expected verified  direct verified
ES256              bearer     208 bytes  verified                  expected verified  direct verified
EdDSA              cookie     208 bytes  verified                  expected verified  direct verified
EdDSA              bearer     208 bytes  verified                  expected verified  direct verified
ML-DSA-44          cookie   3,355 bytes  verified                  expected verified  direct verified
ML-DSA-44          bearer   3,355 bytes  verified                  expected verified  direct verified
SLH-DSA-SHA2-128s  cookie  10,613 bytes  rejected by proxy         expected rejected  direct verified
SLH-DSA-SHA2-128s  bearer  10,613 bytes  rejected by proxy         expected rejected  direct verified
SLH-DSA-SHA2-128f  cookie  22,922 bytes  rejected by proxy         expected rejected  direct verified
SLH-DSA-SHA2-128f  bearer  22,922 bytes  rejected by proxy         expected rejected  direct verified
```

The JSON on stdout, with `layers` left out and `results` cut to two of its twelve entries:

```json
{
  "ok": true,
  "proxy_url": "http://127.0.0.1:59242",
  "app_url": "http://127.0.0.1:59243",
  "run_dir": "/var/folders/jp/6z_3s2b96kgdyxxg83f56cwh0000gn/T/transport-stack-1rx_1k4p",
  "browser": {
    "version": "156.0.8078.4",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36"
  },
  "algorithms": [
    "RS256",
    "ES256",
    "EdDSA",
    "ML-DSA-44",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-128f"
  ],
  "logs": {
    "browser": "/var/folders/jp/6z_3s2b96kgdyxxg83f56cwh0000gn/T/transport-stack-1rx_1k4p/logs/browser.log",
    "proxy_access": "/var/folders/jp/6z_3s2b96kgdyxxg83f56cwh0000gn/T/transport-stack-1rx_1k4p/logs/proxy-access.log",
    "proxy_error": "/var/folders/jp/6z_3s2b96kgdyxxg83f56cwh0000gn/T/transport-stack-1rx_1k4p/logs/proxy-error.log",
    "app": "/var/folders/jp/6z_3s2b96kgdyxxg83f56cwh0000gn/T/transport-stack-1rx_1k4p/logs/app.log"
  },
  "results": [
    {
      "algorithm": "ML-DSA-44",
      "transport": "cookie",
      "token_bytes": 3355,
      "expected": "verified",
      "outcome": "verified",
      "rejected_by": null,
      "ok": true,
      "page_status": 200,
      "cookie_stored": true,
      "evidence": "verified: the browser sent the 3,355-byte token as a jwt cookie through nginx, and the application verified it; both nonces are in browser.log, proxy-access.log, and app.log",
      "issue": {
        "url": "http://127.0.0.1:59242/api/token/issue?alg=ML-DSA-44&delivery=cookie&nonce=8c6faf252a9e8f4d7b970185a1cc801b",
        "nonce": "8c6faf252a9e8f4d7b970185a1cc801b",
        "status": 200,
        "logs": {
          "browser": true,
          "proxy_access": true,
          "proxy_error": false,
          "app": true
        }
      },
      "verify": {
        "url": "http://127.0.0.1:59242/api/token/verify?nonce=e7da9cf156cd39162fa24bcb612866ba",
        "nonce": "e7da9cf156cd39162fa24bcb612866ba",
        "status": 200,
        "body": {
          "layer": "application",
          "verified": true,
          "algorithm": "ML-DSA-44",
          "source": "cookie",
          "token_bytes": 3355,
          "claims": {
            "sub": "benchmark-user",
            "name": "JWT Benchmark",
            "role": "reader"
          },
          "experiment_key": true,
          "received": {
            "headers": 15,
            "header_bytes": 3912,
            "cookie_bytes": 3359,
            "authorization_bytes": null
          }
        },
        "logs": {
          "browser": true,
          "proxy_access": true,
          "proxy_error": false,
          "app": true
        }
      },
      "direct": {
        "url": "http://127.0.0.1:59243/api/token/verify?nonce=217382fce3631dae8906b4b98f7401c8",
        "nonce": "217382fce3631dae8906b4b98f7401c8",
        "status": 200,
        "verified": true
      }
    },
    {
      "algorithm": "SLH-DSA-SHA2-128f",
      "transport": "bearer",
      "token_bytes": 22922,
      "expected": "rejected",
      "outcome": "rejected",
      "rejected_by": "proxy",
      "ok": true,
      "page_status": 200,
      "cookie_stored": null,
      "evidence": "proxy: the browser got status 400 for the verify request; proxy-access.log: \"127.0.0.1 [10/Nov/2026:16:42:58 -0500] \"GET /api/token/verify?nonce=92a66f7797b0ed7e79d7f472f455f420 HTTP/1.1\" 400 233 request_length=190 upstream_status=-\"; proxy-error.log: \"2026/11/10 16:42:58 [info] 4673#9057292: *46 client sent too long header line: \"Authorization: Bearer eyJhbGciOiJT[...].eyJzdWIiOiJi[...].P74YPLMWoduG[...]...\" while reading client request headers, client: 127.0.0.1, server: , request: \"GET /api/token/verify?nonce=92a66f7797b0...\"; its nonce is not in app.log, so nginx did not forward it",
      "issue": {
        "url": "http://127.0.0.1:59242/api/token/issue?alg=SLH-DSA-SHA2-128f&delivery=body&nonce=736cb4d387f99b4fe91782e2aa070162",
        "nonce": "736cb4d387f99b4fe91782e2aa070162",
        "status": 200,
        "logs": {
          "browser": true,
          "proxy_access": true,
          "proxy_error": false,
          "app": true
        }
      },
      "verify": {
        "url": "http://127.0.0.1:59242/api/token/verify?nonce=92a66f7797b0ed7e79d7f472f455f420",
        "nonce": "92a66f7797b0ed7e79d7f472f455f420",
        "status": 400,
        "body": null,
        "logs": {
          "browser": true,
          "proxy_access": true,
          "proxy_error": true,
          "app": false
        }
      },
      "direct": {
        "url": "http://127.0.0.1:59243/api/token/verify?nonce=0a6c0c2159d9606e411b96dea7518bc6",
        "nonce": "0a6c0c2159d9606e411b96dea7518bc6",
        "status": 200,
        "verified": true
      }
    }
  ]
}
```

The `evidence` of the other two SLH-DSA pairs in the same run:

- SLH-DSA-SHA2-128s cookie: `browser: the issue response carried a 10,652-byte Set-Cookie (browser.log) whose name + value is 10,616 bytes, but BrowserContext.cookies() lists no jwt cookie afterwards`
- SLH-DSA-SHA2-128f cookie: `proxy: the browser got status 502 for the issue request; proxy-access.log: "127.0.0.1 [10/Nov/2026:16:42:58 -0500] "GET /api/token/issue?alg=SLH-DSA-SHA2-128f&delivery=cookie&nonce=2ede769f9b909778576918fd53989953 HTTP/1.1" 502 559 request_length=677 upstream_status=502"; proxy-error.log: "2026/11/10 16:42:58 [error] 4673#9057292: *42 upstream sent too big header while reading response header from upstream, ..."; app.log shows the application answered 200: ...` (shortened here)

These results are observations at one token size per configuration, not measured boundaries.

## Support for Sprint 2 tasks

- **S2-02 (test environment):** done. The [token endpoints](#token-endpoints) are in `route()` in [scripts/transport_app.py](scripts/transport_app.py), next to `/api/echo`; they issue a token as an ordinary `Set-Cookie` or in a JSON body and verify a token from the `jwt` cookie or a Bearer header with the adapters in [scripts/algorithms.py](scripts/algorithms.py). The test page is served by the application through nginx. `scripts/transport_stack.py tokens` sends each configuration's fixture token from that page with `fetch()`, as a cookie and as a Bearer header, and finds each request's nonce in every layer's log: `browser.log` (the browser's request headers and cookie jar), `proxy-access.log` and `proxy-error.log`, and `app.log` (the received header sizes). See [The token check](#the-token-check) for the results and why the SLH-DSA pairs are rejected at the default limits.
- **S2-03 (byte accounting):** the echo returns every header the application received, and `proxy-access.log` records every request nginx saw, including rejected ones, with nginx's `request_length` (request line, headers, and body). For a request nginx rejects, `request_length` covers only the part it had parsed (80 bytes for a request with a 16 KiB header in a trial run), so the size of a rejected request has to come from the client. Because nginx rewrites `Host` and removes hop-by-hop headers, browser-side and application-side byte counts differ; count both, for example from the `request` events in `browser.log` and the `received` sizes of the verify endpoint. `X-Transport-Padding` is the agreed name for a padding header. The issue endpoint signs only the unpadded fixture, so size-controlled tokens need a new parameter or endpoint.
- **S2-04 (cookie sweep):** the application sets the cookie with `Set-Cookie`, the browser decides whether to store it (Chromium's 4,096-byte name + value limit), `BrowserContext.cookies()` shows whether it was stored, the echo shows whether it was sent, and the logs show which layer rejected the request (nginx 400 in `proxy-access.log` and `client sent too long header line` in `proxy-error.log`, waitress 431 in the response and a `rejected by waitress` line in `app.log`). `Set-Cookie` responses larger than `proxy_buffer_size` fail at nginx with 502 before the browser sees them; that limit is 4 KiB on WSL2 and 16 KiB on the Mac.
- **S2-05 (Bearer sweep):** from the browser, send `fetch(url, {headers: {Authorization: "Bearer <token>"}})` with `page.evaluate()` from the test page (same origin, so no CORS preflight). From a non-browser client, use `http_get(url, headers={"Authorization": "Bearer <token>"})` in [scripts/transport_stack.py](scripts/transport_stack.py), which uses `http.client` directly and ignores proxy environment variables, against `proxy_url` or directly against `app_url`. To raise the first rejecting limit once, change `large_client_header_buffers` in [transport/nginx.conf.template](transport/nginx.conf.template) for nginx, or `max_request_header_size` in the `waitress.serve(...)` call in [scripts/transport_app.py](scripts/transport_app.py) for waitress, and record the change. Chromium's cookie limit cannot be raised.
- For manual exploration, `serve` keeps the stack running so the page, the logs, and other clients can be used against it.

## Limitations

- **Tested platforms:** macOS 26.5.1 (build 25F80) on an Apple M5 Pro (arm64), on November 4, 2026 (and the `tokens` check on November 10, 2026); and Ubuntu 24.04.4 LTS (glibc 2.39) on WSL2 (Linux 6.6.87.2-microsoft-standard-WSL2, x86_64), on November 12, 2026. Both used Python 3.15.2 from conda-forge, and on both `setup.sh` exited 0 and `check` passed. On WSL2, conda resolved nginx 1.31.8 to build `hee9aced_1` rather than the `h1ababa1_0` found by the earlier dry run; the version is the same. `install-deps` was not exercised, because the WSL2 distribution already had Chromium's libraries. `getconf PAGESIZE` reports 4,096 on the WSL2 machine, which confirms the 4 KiB `proxy_buffer_size` default there. The `tokens` check passed on WSL2 on November 12, 2026.
- **Plain HTTP/1.1 on 127.0.0.1:** there is no TLS. Cookies with the `Secure` attribute or a `__Secure-`/`__Host-` prefix may be handled differently than on an HTTPS site, so S2-04 must check how Chromium treats them on `http://127.0.0.1` before using them, or add TLS. HTTP/2 and HTTP/3 header compression (HPACK and QPACK) is out of scope; nginx applies its buffer limits to compressed header fields there, so the byte counts here do not carry over.
- **Documented, not measured:** the limits table lists documented defaults. The test suite only checks them coarsely (a header of one quarter of the smallest documented limit passes; twice nginx's or waitress's limit is rejected). Exact boundaries are S2-04 and S2-05 work.
- **Logged sizes are not wire bytes:** `app.log` and the verify endpoint's `received` sizes are rebuilt from the WSGI environ (lowercased names, values stripped by waitress, repeated headers joined, `Host` as nginx rewrote it), so they are not the raw bytes on the wire; only the `rejected by waitress` line reports waitress's own byte count. `browser.log` is written on the Playwright side from what Chromium reports through `Request.all_headers()`, `Response.all_headers()`, and `BrowserContext.cookies()`, because Chromium keeps no request log of its own. Exact byte accounting is S2-03 work.
- **One token size, default limits:** `tokens` sends only the unpadded fixture token of each configuration, so its results are observations at one size, not measured boundaries, and `expected` is a coarse prediction from documented defaults. At those defaults the two SLH-DSA tokens cannot cross browser → proxy, so four of the twelve pairs are rejected by design and verify only when sent directly to the application; by the team's decision for S2-02, no limit is raised and no cookie is split (S2-05 and S3-02 work). The layer that rejects the SLH-DSA-SHA2-128s cookie depends on nginx's `proxy_buffer_size`, 16 KiB on Apple Silicon and 4 KiB on x86_64 Linux: it was the browser on this Mac and nginx (502) on WSL2.
- **nginx on macOS:** the `timer_resolution` workaround above is needed with the conda-forge osx-arm64 build, and that build prints `Unknown error` for every error number in its error log (the number itself is correct).
- **One browser engine:** only Chromium. Firefox and WebKit, and other proxies or servers, are left until the first path is complete.
- **Shared browser cache:** the Chromium build lives in Playwright's per-user cache, outside the environment. Removing the cache, or installing a different Playwright version without `--no-remove`, can remove it; `setup.sh` downloads it again.
