# AGENTS.md

This repository is a Rust GMP/GVMD client and protocol ecosystem. Start with the project direction before editing protocol behavior:

- `README.md` explains the public positioning and quick-start examples.
- `docs/ROADMAP.md` defines the support direction, compatibility stance, and current follow-up work.
- `docs/STATUS.md` summarizes crate coverage, version negotiation, tests, and known implementation status.
- `docs/agent-code-map.md` is the fast code tour for coding agents.

## Workflow Rules

- Check `docs/agent-code-map.md` before broad repo exploration.
- Keep edits scoped to the crate/domain that owns the behavior.
- Do not treat `target/`, `tmp/`, or old journal/spec branches as source of truth.
- Do not rewrite public APIs just to mirror python-gvm naming.
- For docs-only changes, do not run the Rust test suite unless the docs include checked examples.

## Change Guidance

- Model current GMP/GVMD semantics directly. Do not copy python-gvm API shape by default.
- Keep python-gvm compatibility where it helps migration or validates interoperability.
- When changing a command, check command builder XML, response parsing, version gating, mock-server behavior, and docs.
- When fixing protocol drift, prefer real gvmd behavior over mock-server behavior.
- Keep typed helpers source-compatible unless the existing API is actively misleading.
- If an existing dirty worktree has unrelated changes, leave them alone and use a clean worktree when needed.

## Common Commands

```bash
cargo fmt --all
cargo test --workspace
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
make test-integration
```

Use focused crate or test targets while iterating, then run the relevant workspace command before handing off. See `docs/agent-code-map.md` for targeted tests by change type.
