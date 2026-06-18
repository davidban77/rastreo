# Contributing to rastreo

## Building

```bash
cargo build --workspace
```

## Testing

```bash
cargo test --workspace
```

## Linting and Formatting

Both must pass before committing:

```bash
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

To apply formatting automatically:

```bash
cargo fmt --all
```

## Commit Message Format

This project uses a conventional commit style:

```
<type>(<scope>): <short description>
```

Types:

- `feat` — new capability or behavior
- `fix` — bug fix
- `test` — adding or updating tests
- `docs` — documentation only
- `chore` — tooling, config, or housekeeping

Scope examples: `core`, `cli`, `server`, `ci`.

The first line must be 72 characters or fewer. Use the body for context when the change is non-obvious.

## Pull Request Process

All changes to `main` go through pull requests. The expected workflow:

1. **Create a feature branch** off `main`:

   ```bash
   git checkout main && git pull
   git checkout -b feat/my-new-feature
   ```

   Use a descriptive branch name prefixed with the change type: `feat/`, `fix/`, `docs/`, etc.

2. **Open a pull request** against `main`. Fill in the PR description with a summary, the concrete changes, and a test plan.

3. **Use a conventional commit as the PR title.** Since PRs are squash-merged, the PR title becomes the commit message on `main`. Examples:

   ```
   feat(core): add SNMP prober
   fix: resolve panic in deduplication path
   docs: update CLI reference for new flag
   ```

4. **Wait for CI.** Build, test, clippy, and fmt jobs must pass.

5. **Get a review.** At least one approving review is required.

6. **Squash merge.** Use the "Squash and merge" option in GitHub. The PR title is used as the commit message.

## Project Structure

The project is a Cargo workspace with three crates:

- `rastreo-core` — library crate with all domain logic (probers, fusion, classification, encoders, sinks)
- `rastreo` — CLI binary (thin layer over core)
- `rastreo-server` — HTTP control plane

All business logic belongs in `rastreo-core`. The CLI and server are delivery mechanisms only.

## Error Handling

- Use `thiserror` in `rastreo-core` for typed library errors.
- Use `anyhow` in `rastreo` and `rastreo-server` for application-level errors.
- Never call `unwrap()` in library code.

## Adding Extension Points

Probers, encoders, and sinks are added by implementing the matching trait in `rastreo-core` and registering the implementation in its factory. Skill guides under `.claude/skills/` will document the exact steps and quality checklist for each extension type.
