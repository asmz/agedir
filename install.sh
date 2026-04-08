#!/bin/sh
set -e

REPO="asmz/agedir"
BINARY="agedir"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# OS detection
OS="$(uname -s)"
case "${OS}" in
  Linux)  OS="linux" ;;
  Darwin) OS="darwin" ;;
  *)
    echo "Unsupported OS: ${OS}" >&2
    exit 1
    ;;
esac

# Arch detection
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: ${ARCH}" >&2
    exit 1
    ;;
esac

# Version resolution
if [ -z "${AGEDIR_VERSION}" ]; then
  AGEDIR_VERSION="$(curl -sSLf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
fi

if [ -z "${AGEDIR_VERSION}" ]; then
  echo "Failed to resolve latest version" >&2
  exit 1
fi

ARCHIVE="${BINARY}_${AGEDIR_VERSION#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${AGEDIR_VERSION}/${ARCHIVE}"

echo "Installing ${BINARY} ${AGEDIR_VERSION} (${OS}/${ARCH})..."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

curl -sSLf "${URL}" -o "${TMP_DIR}/${ARCHIVE}"
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"

cp "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
chmod 755 "${INSTALL_DIR}/${BINARY}"

echo "Installed to ${INSTALL_DIR}/${BINARY}"
"${INSTALL_DIR}/${BINARY}" --version
