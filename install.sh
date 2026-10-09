#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Install TWA for the current Linux user.

The installer finds Python 3.12+, creates a private virtual environment,
installs the `twa` command, and starts Antigravity login when OmniRoute is
already installed. It does not install OmniRoute or request a Google password.

Optional test/packaging overrides: TWA_INSTALL_DIR and TWA_BIN_DIR.
EOF
  exit 0
fi
if [[ "$#" -ne 0 ]]; then
  echo "Usage: bash install.sh [--help]" >&2
  exit 2
fi

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
user_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
if [[ -z "$user_home" ]]; then
  echo "Could not find the current user's home directory." >&2
  exit 1
fi

python_bin=""
for candidate in python3.14 python3.13 python3.12 python3; do
  candidate_path="$(command -v "$candidate" || true)"
  if [[ -n "$candidate_path" ]] && "$candidate_path" -c 'import sys; raise SystemExit(sys.version_info < (3, 12))' 2>/dev/null; then
    python_bin="$candidate_path"
    break
  fi
done
if [[ -z "$python_bin" ]]; then
  echo "TWA needs Python 3.12 or newer. Install it with your Linux distribution's package manager, then rerun: bash install.sh" >&2
  exit 2
fi

data_root="${XDG_DATA_HOME:-$user_home/.local/share}"
bin_root="${XDG_BIN_HOME:-$user_home/.local/bin}"
install_root="${TWA_INSTALL_DIR:-$data_root/twa}"
bin_dir="${TWA_BIN_DIR:-$bin_root}"
venv_dir="$install_root/venv"

mkdir -p "$install_root" "$bin_dir"
if "$python_bin" -c 'import ensurepip' >/dev/null 2>&1; then
  "$python_bin" -m venv "$venv_dir"
else
  # Debian may split venv/ensurepip into an optional system package. Bootstrap
  # virtualenv under TWA's private data directory rather than changing system Python.
  bootstrap_dir="$install_root/bootstrap"
  if ! PYTHONPATH="$bootstrap_dir" "$python_bin" -c 'import virtualenv' >/dev/null 2>&1; then
    "$python_bin" -m pip --quiet install --disable-pip-version-check --break-system-packages \
      --target "$bootstrap_dir" virtualenv
  fi
  PYTHONPATH="$bootstrap_dir${PYTHONPATH:+:$PYTHONPATH}" \
    "$python_bin" -m virtualenv --quiet --no-download --clear "$venv_dir"
fi
"$venv_dir/bin/python" -m pip --quiet install --disable-pip-version-check "$project_root"
ln -sfn "$venv_dir/bin/twa" "$bin_dir/twa"

if [[ -z "${TWA_BIN_DIR:-}" ]] && [[ ":$PATH:" != *":$bin_dir:"* ]]; then
  shell_name="$(basename "${SHELL:-/bin/bash}")"
  case "$shell_name" in
    zsh) shell_rc="$user_home/.zshrc" ;;
    bash) shell_rc="$user_home/.bashrc" ;;
    *) shell_rc="$user_home/.profile" ;;
  esac
  if ! grep -Fq '# TWA user command path' "$shell_rc" 2>/dev/null; then
    {
      printf '\n# TWA user command path\n'
      printf 'case ":$PATH:" in *":%s:"*) ;; *) export PATH="%s:$PATH" ;; esac\n' "$bin_dir" "$bin_dir"
    } >> "$shell_rc"
    echo "Added $bin_dir to $shell_rc. Open a new terminal to use the TWA command everywhere."
  fi
fi

echo "TWA installed with $python_bin. Command: $bin_dir/twa"
"$bin_dir/twa" version

if command -v omniroute >/dev/null 2>&1; then
  echo "Starting Antigravity login through OmniRoute."
  if ! "$bin_dir/twa" login; then
    echo "TWA is installed; OmniRoute login did not complete. Check that its server is configured and running, then run: twa login"
  fi
else
  echo "A working Linux OmniRoute CLI was not found. Install and configure it, start its server, then run: twa login"
fi
