default:
    @just --list

# Run all test suites (offline, stubbed API)
test: test-go test-py test-ts

test-go:
    go vet ./... && go test ./...

test-py:
    cd python && uv run -q --with pytest --with-editable . pytest -q tests

test-ts:
    npm test --silent

# Build CLI and install to ~/.local/bin
install:
    go build -o ~/.local/bin/tgnotify ./cmd/tgnotify
    @echo "installed ~/.local/bin/tgnotify"
