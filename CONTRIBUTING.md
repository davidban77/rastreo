# Contributing to rastreo

## Building

```bash
cargo build --workspace
```

## Testing

```bash
cargo test --workspace
```

## Benchmarks

```bash
cargo bench -p rastreo-core            # full run, ~3 minutes
cargo bench -p rastreo-core -- --test  # one iteration of each, ~2 seconds
```

`rastreo-core/benches/emit_path.rs` measures sink dispatch and encoder cost at 65, 650, and 6500 records. Both sides of every comparison are hard-coded as separate arms so criterion measures them within a single process. Do not compare `--save-baseline` snapshots taken from different runs: arms within one run resolve differences down to ~0.4%, while the same arm measured in two runs on an otherwise idle laptop drifts by up to 6%. Report results in ns/record — a percentage means nothing until you name which arm is the denominator.

The benchmark does not run in CI, but `cargo clippy --workspace --all-targets` compiles it, so a bench that stops building fails the lint job. The permanent regression guard is `rastreo-core/tests/emit_path_guards.rs`: it counts heap allocations per record, which is deterministic and machine-independent, and it runs as part of `cargo test --workspace`.

Criterion depends on `alloca`, whose build script compiles a small C source file, so any `--all-targets` build needs a working C compiler. Linking Rust binaries on Linux and macOS already requires one, so this is normally satisfied.

## Linting and Formatting

All three must pass before committing:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo hack --each-feature --workspace clippy --all-targets -- -D warnings
```

The third one needs `cargo install cargo-hack`. A workspace build enables most optional features at once, and a lint on a feature-gated type can go quiet in that shape — linting each feature on its own is what catches it. `task lint` runs all three.

To apply formatting automatically:

```bash
cargo fmt --all
```

## Commit Message Format

This project uses a conventional commit style:

```
<type>(<scope>): <short description>
```

Types, and the changelog section each one lands in:

| Type | Section |
|---|---|
| `feat` — new capability or behavior | Features |
| `fix` — bug fix | Bug Fixes |
| `perf` — same behavior, measurably cheaper | Performance |
| `docs` — documentation only | Documentation |
| `refactor` — no behavior change | Refactoring |
| `ci` — workflows and pipelines | CI/CD |
| `chore` — tooling, config, housekeeping | Miscellaneous |
| `test` — tests only | not in the changelog |
| `build` — build system | not in the changelog |
| `deps` — dependency bumps | not in the changelog |

Scope examples: `core`, `cli`, `server`, `ci`.

The first line must be 72 characters or fewer. Use the body for context when the change is non-obvious.

## Breaking Changes

Mark a breaking change with `!` after the scope — `feat(core)!: require every sink to declare its kind`. That is what puts the change under **⚠ BREAKING CHANGES** in the release notes.

It does not force a major version. `bump-minor-pre-major` is set, so pre-1.0 a breaking change still takes a minor bump: `feat(core)!` in #227 produced 0.10.0, not 1.0.0.

The `!` alone yields a one-line bullet. When the break needs explaining — what stops compiling, what silently changes, what to do instead — put a `BREAKING CHANGE:` paragraph in the **squash commit body** at merge time. release-please copies it into the release notes verbatim. Hand-editing the release PR's `CHANGELOG.md` afterwards does not survive: the next merge regenerates that section.

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
   feat(core)!: require every sink to declare its kind
   ```

4. **Wait for CI.** Build, test, clippy, and fmt jobs must pass.

5. **Get a review.** At least one approving review is required.

6. **Squash merge.** Use the "Squash and merge" option in GitHub. The PR title is used as the commit message. If the change is breaking and needs more than a bullet, add the `BREAKING CHANGE:` paragraph to the squash body here — this is the only point at which it reaches the release notes.

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
