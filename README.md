# Post-Quantum JWTs in Web Transport

This project looks at what happens to JSON Web Token (JWT) web logins when the tokens are signed with NIST's post-quantum signatures, ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). The same JWT is signed with three classical algorithms (RS256, ES256, EdDSA) and three post-quantum ones (ML-DSA-44, SLH-DSA-SHA2-128s and -128f), and each token is sent through a real browser (Chromium), reverse proxy (nginx) and application server (waitress). Each run records the token's size and signing cost, the largest token each layer accepts and which layer rejects the next byte, end-to-end latency and throughput, and what each mitigation changes.

The write-up, recorded runs and design notes are all in [results/](results/): the final report is [FINAL_REPORT.md](results/FINAL_REPORT.md), and [RECOMMENDATIONS.md](results/RECOMMENDATIONS.md) has the comparison tables. A read-only demo of the browser test page runs at [jseara.github.io/Post-Quantum-JWT](https://jseara.github.io/Post-Quantum-JWT/).

The rest of this README covers reproducing the project on your own machine.

## Requirements

- macOS on Apple Silicon, or WSL2 on Windows.
- conda, for example [Miniforge](https://conda-forge.org/download/). Docker, Homebrew and sudo aren't needed.
- Ports 8080 and 8081 free for the test stack. Every server binds to 127.0.0.1 only.

## 1. Create the environment

The setup script builds a pinned conda environment outside the repository: Python 3.15.2, nginx 1.31.8, Playwright 1.64.1 with its Chromium, waitress 3.0.2, cryptography 50.0.2, PyJWT 2.15.1 and pqcrypto 1.0.0. It ends by checking every version.

```bash
git clone https://github.com/jseara/Post-Quantum-JWT.git
cd Post-Quantum-JWT
export TRANSPORT_ENV="$HOME/miniforge3/envs/cis628-transport"
bash transport/setup.sh "$TRANSPORT_ENV"
```

If conda isn't on your PATH, set `CONDA_EXE` first, for example `export CONDA_EXE="$HOME/miniforge3/bin/conda"`. Keep `TRANSPORT_ENV` exported in every terminal you use: the `make` targets run its Python.

## 2. Check the stack

```bash
make check
```

This sends one browser request through Chromium, nginx and waitress, then stops the stack. `make versions` compares the installed versions with the pinned ones.

## 3. Run the experiments

Each target writes a new timestamped run directory and prints a summary.

| Command | What it measures | Output |
| --- | --- | --- |
| `make benchmark` | Token sizes and in-process sign and verify times (RQ1, RQ3) | `results/<time>/` |
| `make sweep` | Largest cookie and Bearer token each layer accepts (RQ2) | `results/transport/<time>/` |
| `make load` | End-to-end latency and throughput through the stack (RQ3) | `results/load/<time>/` |
| `make claims` | Mitigation: smaller claim sets (RQ4) | `results/claims/<time>/` |
| `make cookies` | Mitigation: cookie splitting (RQ4) | `results/cookies/<time>/` |
| `make refs` | Mitigation: reference tokens (RQ4) | `results/refs/<time>/` |
| `make protocols` | The cookie and Bearer sweeps over HTTPS and HTTP/2 | `results/transport/<time>/` |

Size limits are byte counts, so they reproduce exactly on the same platform, except the HTTP/2 Bearer limit, which shifts by a few bytes from run to run. Timings vary by machine. macOS and WSL2 differ on purpose: nginx's default response buffer is one memory page, 16 KiB on Apple Silicon and 4 KiB on WSL2, so cookie limits are lower on WSL2.

## 4. Run the tests

```bash
make test
"$TRANSPORT_ENV/bin/python" scripts/transport_report.py --check
"$TRANSPORT_ENV/bin/python" scripts/transport_pages.py --check
```

`make test` runs the full suite, about 1,000 tests in roughly six minutes; the live tests start and stop their own stacks. The two `--check` commands confirm that the tables in [RECOMMENDATIONS.md](results/RECOMMENDATIONS.md) and the data in the test page match the committed results.

## 5. Try the test page

```bash
make serve
```

Then open <http://localhost:8080/>; from WSL2, the Windows browser reaches the same address. Each button issues or verifies a real token and shows which layer answered. `make logs`, in a second terminal, follows the nginx and application logs, and Ctrl+C stops both servers.

Every command's options, the stack's configuration and the result file formats are documented in [TRANSPORT.md](results/TRANSPORT.md). The README before this rewrite, with the project's sprint-by-sprint status, is kept in [HISTORY.md](results/HISTORY.md).
