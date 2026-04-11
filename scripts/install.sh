#!/usr/bin/env sh

set -eu

PACKAGE_NAME="az-rbac-watch"
COMMAND_NAME="az-rbac-watch"
PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
UV_INSTALL_URL="https://astral.sh/uv/install.sh"

have_command() {
    command -v "$1" >/dev/null 2>&1
}

fetch_url() {
    url="$1"

    if have_command curl; then
        curl -LsSf "$url"
        return
    fi

    if have_command wget; then
        wget -qO- "$url"
        return
    fi

    printf '%s\n' "error: curl or wget is required to download installation assets." >&2
    exit 1
}

ensure_uv_on_path() {
    if have_command uv; then
        return
    fi

    for candidate in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
        if [ -x "$candidate" ]; then
            PATH="$(dirname "$candidate"):$PATH"
            export PATH
            return
        fi
    done
}

install_uv() {
    printf '%s\n' "Installing uv..."
    fetch_url "$UV_INSTALL_URL" | sh
    ensure_uv_on_path

    if ! have_command uv; then
        printf '%s\n' "error: uv was installed but is not available on PATH in this shell." >&2
        printf '%s\n' "Add ~/.local/bin to PATH and re-run the installer." >&2
        exit 1
    fi
}

if ! have_command uv; then
    install_uv
fi

UV_BIN_DIR="$(uv tool dir --bin)"
PATH="$UV_BIN_DIR:$PATH"
export PATH

printf '%s\n' "Installing $PACKAGE_NAME with uv..."
uv tool install --force --python "$PYTHON_VERSION" "$PACKAGE_NAME"

printf '%s\n' "Updating your shell PATH configuration..."
UPDATE_SHELL_OK=1
if ! uv tool update-shell; then
    UPDATE_SHELL_OK=0
    printf '%s\n' "warning: uv could not update your shell configuration automatically." >&2
fi

if [ ! -x "$UV_BIN_DIR/$COMMAND_NAME" ]; then
    printf '%s\n' "error: $COMMAND_NAME was not found in $UV_BIN_DIR after installation." >&2
    exit 1
fi

printf '%s\n' ""
"$UV_BIN_DIR/$COMMAND_NAME" --version

if ! have_command az; then
    printf '%s\n' "warning: Azure CLI (az) is not installed. Install it before running scans against Azure." >&2
fi

printf '%s\n' ""
printf '%s\n' "$COMMAND_NAME is installed."
if [ "$UPDATE_SHELL_OK" -eq 0 ]; then
    printf '%s\n' "Add this directory to your PATH if needed: $UV_BIN_DIR"
fi
printf '%s\n' "Open a new shell if your current session does not see it yet."
printf '%s\n' "Next steps:"
printf '%s\n' "  az login"
printf '%s\n' "  $COMMAND_NAME --help"
printf '%s\n' "  $COMMAND_NAME --install-completion"
