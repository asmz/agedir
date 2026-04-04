# agedir

A CLI tool to bulk-encrypt, decrypt, and place multiple secret files across a project using [age](https://age-encryption.org) encryption and a simple YAML mapping config.

## Overview

Projects often contain multiple secret files scattered across directories — API keys, certificates, Firebase configs, and more. agedir manages them all through a single `agedir.yaml` configuration, letting you:

- **Encrypt** raw files into a storage directory with one command
- **Decrypt** and place them back to their original paths with one command
- **Rekey** all encrypted files when team members join or leave
- **Init** a project by auto-detecting common secret file patterns

agedir ships as a single statically-linked binary (no external `age` installation required) and runs on Windows, macOS, and Linux.

## Installation

### Download binary

Download the latest binary for your platform from the [Releases](https://github.com/asmz/agedir/releases) page.

### Build from source

```sh
go install github.com/asmz/agedir@latest
```

Or clone and build:

```sh
git clone https://github.com/asmz/agedir.git
cd agedir
make build
```

Requires Go 1.21 or later.

## Prerequisites: Generating an age Key Pair

Each team member needs an age key pair. Install age and generate one:

```sh
# macOS
brew install age

# other platforms: https://github.com/FiloSottile/age#installation
age-keygen -o ~/.age/key.txt
# Public key: age1xxxx...xxxx
```

Share the **public key** (`age1...`) with your team to add to `agedir.yaml`. Keep the private key file (`~/.age/key.txt`) secret and never commit it.

For more details, see the [age documentation](https://github.com/FiloSottile/age).

## Quick Start

### 1. Initialize a project

```sh
agedir init
```

Scans the current directory for common secret file patterns and generates an `agedir.yaml` template. Detected file paths are automatically appended to `.gitignore`.

### 2. Edit `agedir.yaml`

Add your team's age public keys to `recipients`:

```yaml
version: "1"
recipients:
  - age1xxxx...xxxx  # alice
  - age1yyyy...yyyy  # bob
storage_dir: .agedir/secrets
mapping:
  - raw: android/app/google-services.json
    enc: google-services.json.age
  - raw: ios/Runner/GoogleService-Info.plist
    enc: GoogleService-Info.plist.age
```

### 3. Encrypt

```sh
agedir encrypt
```

Reads each `raw` file and writes the age-encrypted output to `storage_dir/enc`. Commit the `storage_dir` contents to your repository.

### 4. Decrypt

```sh
agedir decrypt -i ~/.age/key.txt
```

Decrypts each encrypted file and places it at the configured `raw` path. Run this when setting up a new environment.

## Commands

### `agedir init`

Scan the project and generate an initial `agedir.yaml`.

```sh
agedir init [--config agedir.yaml]
```

Prompts for confirmation before overwriting an existing config.

### `agedir encrypt`

Encrypt all raw files according to the config.

```sh
agedir encrypt [--config agedir.yaml] [--dry-run]
```

### `agedir decrypt`

Decrypt all encrypted files according to the config.

```sh
agedir decrypt [--identity|-i <keyfile>] [--passphrase|-p] \
               [--verify] [--dry-run] [--config agedir.yaml]
```

| Flag | Description |
|------|-------------|
| `-i, --identity` | Path to age private key file |
| `-p, --passphrase` | Decrypt using passphrase (reads from `AGEDIR_PASSPHRASE` env or terminal prompt) |
| `--verify` | Skip writing if the existing file's SHA-256 hash matches |
| `--dry-run` | Print files to be processed without writing anything |
| `--config` | Path to `agedir.yaml` (default: current directory) |

### `agedir rekey`

Re-encrypt all files with the current `recipients` list.

```sh
agedir rekey [--config agedir.yaml]
```

Use this after adding or removing team members from `recipients`.

## Configuration

`agedir.yaml` schema:

```yaml
version: "1"               # required
recipients:                # required; one or more age public keys
  - age1...
storage_dir: .agedir/secrets  # optional; default: .agedir/secrets
mapping:                   # required; one or more raw/enc pairs
  - raw: path/to/secret.txt  # path relative to project root (original file)
    enc: secret.txt.age      # path relative to storage_dir (encrypted file)
```

## Identity Resolution

`agedir decrypt` resolves the decryption identity in the following order:

1. `--identity` flag (private key file path)
2. `AGEDIR_IDENTITY` environment variable (private key file path)
3. `AGEDIR_PASSPHRASE` environment variable (passphrase, when `-p` is set)
4. Interactive terminal prompt (passphrase, when `-p` is set)

## Security Notes

- **Raw files** (`raw` paths) are added to `.gitignore` by `agedir init` — never commit them.
- **Encrypted files** (`storage_dir`) are safe to commit.
- Passphrases are never passed as command-line arguments (avoids exposure via `ps`).
- Encrypted files are written atomically (temp file + rename) to prevent corruption on interruption.

## Default Scan Patterns

`agedir init` detects the following file patterns:

| Pattern | Example |
|---------|---------|
| `*.jks` | Android Keystore |
| `*.p12` | PKCS#12 certificate |
| `google-services*.json` | Firebase Android config |
| `GoogleService-Info*.plist` | Firebase iOS config |
| `*.pem`, `*.key` | TLS certificates / private keys |

### Scan Exclusion Rules

Directories are excluded from scanning at the **directory level**, not the file level:

- **git-ignored directories**: If a directory is ignored by git (via any `.gitignore` in the repository), it is skipped entirely along with all its contents. This prevents third-party package directories such as `vendor/`, `node_modules/`, and `Pods/` from polluting the results.
- **Built-in fallback list**: When git is unavailable, the following directories are excluded by default: `node_modules/`, `.bundle/`, `Pods/`, `.dart_tool/`.

> **Note:** Individual files that are git-ignored are still detected as long as their parent directory is not git-ignored. This is intentional — raw secret files are typically gitignored at the file level, and `agedir init` is designed to find and manage exactly those files.
>
> If you store secrets inside a git-ignored directory (e.g., a `secrets/` directory that is itself gitignored), those files will not be detected automatically. Add them to `agedir.yaml` manually.

## Cross-Platform Builds

```sh
make cross-build
```

Produces binaries for darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, windows/amd64, and windows/arm64 in the `dist/` directory. All builds use `CGO_ENABLED=0` for pure Go static linking.

## License

MIT — see [LICENSE](LICENSE).
