.PHONY: all build check test test-all fmt clippy doc deny clean setup-hooks coverage

# Default: full check cycle
all: fmt clippy test doc

# Build
build:
	cargo build --workspace --all-features

# Quick check (no codegen)
check:
	cargo check --workspace --all-features

# Run unit tests
test:
	cargo test --workspace

# Run all tests including integration and feature-gated
test-all:
	cargo test --workspace --all-features

# Format code
fmt:
	cargo fmt --all

# Format check (CI)
fmt-check:
	cargo fmt --all -- --check

# Lint
clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

# Documentation (with warnings as errors)
doc:
	RUSTDOCFLAGS="-Dwarnings" cargo doc --workspace --all-features --no-deps

# Open docs in browser
doc-open:
	RUSTDOCFLAGS="-Dwarnings" cargo doc --workspace --all-features --no-deps --open

# License/advisory check
deny:
	cargo deny check

# Coverage report
coverage:
	cargo llvm-cov --workspace --all-features --html
	@echo "Report: target/llvm-cov/html/index.html"

# Coverage (lcov for CI)
coverage-lcov:
	cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info

# Install pre-commit hooks
setup-hooks:
	@command -v pre-commit >/dev/null 2>&1 || { echo "Install pre-commit: pip install pre-commit"; exit 1; }
	pre-commit install
	pre-commit install --hook-type commit-msg
	pre-commit install --hook-type pre-push
	@echo "Hooks installed: pre-commit (fmt+clippy), commit-msg (conventional), pre-push (test+doc)"

# Install development tools
setup-tools:
	cargo install cargo-deny
	cargo install cargo-llvm-cov
	cargo install cargo-audit
	cargo install cargo-outdated
	cargo install cargo-machete
	@echo "Dev tools installed."

# Audit dependencies for vulnerabilities
audit:
	cargo audit

# Check for outdated dependencies
outdated:
	cargo outdated --workspace

# Check for unused dependencies
machete:
	cargo machete

# Clean build artifacts
clean:
	cargo clean

# Full CI simulation locally
ci: fmt-check clippy test-all doc deny
	@echo "All CI checks passed."
