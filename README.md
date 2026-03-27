# agedir

A CLI tool to bulk-encrypt, decrypt, and place multiple secret files across a project using [age](https://age-encryption.org) encryption and a simple YAML mapping config.

## Overview

Projects often contain multiple secret files scattered across directories — API keys, certificates, Firebase configs, `.env` files, and more. agedir manages them all through a single `agedir.yaml` configuration, letting you:

- **Encrypt** plaintext files into a storage directory with one command
- **Decrypt** and place them back to their original paths with one command
- **Rekey** all encrypted files when team members join or leave
- **Init** a project by auto-detecting common secret file patterns

agedir ships as a single statically-linked binary (no external `age` installation required) and runs on Windows, macOS, and Linux.

<!--

Underconstruction

-->

## License

MIT — see [LICENSE](LICENSE).
