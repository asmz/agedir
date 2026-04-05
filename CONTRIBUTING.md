# Contributing to agedir

Thank you for your interest in contributing to agedir!

## Reporting Issues

- Search [existing issues](https://github.com/asmz/agedir/issues) before opening a new one.
- For security vulnerabilities, please **do not** open a public issue. Instead, report them via GitHub's [private vulnerability reporting](https://github.com/asmz/agedir/security/advisories/new).

## Development Setup

**Prerequisites**: Go 1.26+, mise (optional but recommended)

```sh
git clone https://github.com/asmz/agedir.git
cd agedir

# with mise
mise install

# or directly
go build ./...
go test ./...
```

## Making Changes

1. Fork the repository and create a branch from `main`.
2. Make your changes.
3. Add or update tests as needed.
4. Run the test suite and ensure everything passes:
   ```sh
   go test ./...
   go vet ./...
   ```
5. Open a pull request against `main`.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Keep changes focused — one concern per pull request.
- Do not add unnecessary comments, docstrings, or abstractions beyond what the change requires.

## Commit Messages

Write clear, concise commit messages in the imperative mood:
- `add passphrase support to encrypt command`
- `fix enc path collision when files share the same basename`

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
