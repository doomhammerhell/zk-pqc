# Contributing to ZK-PQC

We strictly enforce a "Zero Tolerance" policy for deviations from our engineering standards to ensure deterministic reproducibility and cryptographic integrity.

## The "Hard-Line" Policy
1. **Formatting**: Your code MUST pass `prettier`, `cargo fmt`, and `scarb fmt`.
2. **Linting**: No warnings are allowed. `cargo clippy -D warnings` is strictly enforced for Rust. Unsafe math is explicitly prohibited.
3. **Tests**: 100% pass rate is mandatory across all target environments.
4. **GitFlow**: All work must be submitted via Pull Requests targeting the `main` branch. Direct commits to `main` are strictly forbidden.
5. **Signed Commits**: All commits must be cryptographically signed via GPG/SSH.

## Commit Message Convention
We use conventional commits (`feat:`, `fix:`, `docs:`, `chore:`, etc.) to trigger automatic semantic versioning.

## Development Container
You **MUST** use the provided DevContainer (`.devcontainer`) to ensure deterministic tooling versions and pre-installed extensions match production build behaviors perfectly.
