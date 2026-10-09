# TWA — Terminal Web Agent

TWA is a local-first CTF investigation CLI. It keeps original evidence intact, extracts bounded facts from common challenge files, records every run as a resumable JSON session, and optionally asks a configured OmniRoute server for a bounded analysis plan. Network mode is passive: it makes scoped GET requests only, does not follow redirects, and requires `--scope` to match the target host.

## Install

Requires Python 3.12 or newer. Linux, macOS, and Windows are supported.

On Linux, run the installer once. It finds Python itself, installs TWA in a private virtual environment, adds the `twa` command to the user's path, and starts Antigravity login when OmniRoute is already installed:

```sh
bash ./install.sh
```

On Windows PowerShell, install with `python -m pip install .`; the `twa` command is then available directly. The Linux installer is `install.sh`.

## Quick start

```sh
twa -f "./challenge.zip" --s
twa -u "https://challenge.example" --scope "challenge.example" --s
twa models
twa doctor
twa sessions
twa report SESSION_ID
```

Local analysis works without an AI account. AI planning is used only when OmniRoute is reachable and a model has been selected or configured. If a provider refuses or content-filters a request, TWA does not try to bypass that decision, repeat the same prompt, or search other models for a less restrictive answer. It classifies and reports the refusal, keeps the session and local findings, then completes the local analysis. Transient provider failures get bounded retries; oversized context gets one shorter evidence summary. `--offline` prevents provider and target network requests.

## OmniRoute and Antigravity

Install and configure OmniRoute on Linux. Keep its server running in one terminal:

```sh
npm install --global omniroute
omniroute setup
omniroute serve
```

In a second terminal, install TWA and connect Antigravity automatically:

```sh
bash ./install.sh
twa models
twa config model
```

`twa login` delegates Antigravity authentication to `omniroute oauth start --provider antigravity`. It never asks for a Google password or reads another app's tokens. On Linux without a graphical session, the browser is not opened automatically; OmniRoute prints the authorization URL in the terminal. For a remote Linux host, open an SSH port forward using the OmniRoute listener port and keep it active until login finishes; the port can be checked with `omniroute status`. Pass `--browser` to explicitly ask OmniRoute to open a browser. Model discovery uses `omniroute models --json`. The OmniRoute server must be running and configured first. TWA accepts `OMNIROUTE_BASE_URL` and `OMNIROUTE_API_KEY` from the environment for its OpenAI-compatible endpoint; secrets are never written to TWA config or reports.

## Scope and safety

Remote target analysis requires an explicit `--scope` hostname exactly matching the URL hostname. It performs one homepage GET and, when present on the same origin, reads `/robots.txt` and `/sitemap.xml`. Redirects are not followed and discovered links are not crawled. TWA does not perform exploitation, credential attacks, fuzzing, or execute submitted binaries. Network limits, per-request timeouts, file count, archive bytes, and per-file evidence size are bounded.

## Configuration

Configuration is read from `.twa/config.yaml` in the current directory. Run `twa config` to show its path and `twa config model` to select one of the currently discovered model IDs. The file contains nonsecret settings only.

```yaml
application:
  default_silent: true
ai:
  preferred_model_family: opus
  model: null
agent:
  max_steps: 10
  max_retries: 2
  timeout: 90
recovery:
  enabled: true
  retry_transient_errors: true
  continue_local_analysis: true
security:
  scope_confirmation: required
  network_rate_limit: 2
  preserve_original_files: true
reporting:
  save_json: true
  redact_credentials: true
```

## Features and limitations

- Local directory, bounded ZIP, text, image signature/PNG chunks, and classic PCAP inspection.
- Base64, Base32, hex, ROT13, XOR single-byte scoring, and common flag candidates.
- Flag matches are reported as candidates and remain unverified; TWA never marks a challenge solved without an authorized checker.
- Provider refusal and content filtering are classified distinctly from authentication, rate limit, context, network, and malformed-response failures.
- External PCAP dissection, advanced steganography, binary execution, active web testing, OSINT crawling, and Ghidra integration are not implemented. Image EXIF extraction is available when Pillow is installed.

## Development

```sh
python -m pytest -q
ruff check .
python -m build
```

