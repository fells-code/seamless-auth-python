# AGENTS.md

This file is for coding agents working in `seamless-auth-python`, the Seamless Auth server adapter
for Python, with FastAPI and Django bindings.

## Working Standards (fells-code baseline)

These rules apply to every repository in the fells-code org. Repo-specific
guidance may extend them but must not contradict them.

### Attribution

- Commit and open PRs solely under the repository owner's identity. Never
  commit under an agent or assistant identity.
- Never attribute work to an AI assistant: no `Co-Authored-By: Claude` (or any
  assistant) trailers, no "Generated with" / "Created with Claude" notes, and no
  assistant branding or emoji anywhere in commit messages, PR or issue titles
  and descriptions, changesets, code comments, or docs.

### Comments

- Comment only when the code genuinely needs explaining: a non-obvious reason, a
  gotcha, or an invariant. Never narrate what the code plainly does.

### TODOs

- Every `TODO`/`FIXME` must reference a ticket, e.g. `// TODO(#123): ...`.
  Do not leave a bare TODO. If no ticket exists, create one first.

### Commits & branches

- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, `test:`).
- Descriptive branch names (`feat/...`, `fix/...`); never a `claude/` or other
  tool-generated prefix.

### Public-facing text

- No em dashes in commit messages, code comments, PR or issue text, changesets,
  or docs. Use a comma, parentheses, or a separate sentence.

### Before declaring work done

- All code quality checks must pass before you open a PR or call the work done.
  Run them and report the real output; do not open a PR while any check is failing.
- Match the surrounding code's style, naming, and comment density.

## Checks

Tooling is [uv](https://docs.astral.sh/uv/). Development runs on Python 3.11, the minimum.

| Check | Command |
| --- | --- |
| Lint | `uv run ruff check .` |
| Format | `uv run ruff format --check .` |
| Types | `uv run mypy` (strict) |
| Tests | `uv run pytest` |
| Conformance | see README, "Conformance" (both reference apps) |

CI runs the checks on Python 3.11 to 3.14. 3.11 resolves Django 5.2 LTS and later versions the
current Django, so both are covered. Do not use language or standard library features newer than
3.11. `uv.lock` is committed so CI builds what was tested.

## Shape

- `src/seamless_auth/_adapter.py`: `Adapter`, the request pipeline, the upstream call, manifest
  routes, credential resolution (with silent refresh), session verification, refresh, logout, the
  guard, the cross-site check.
- `src/seamless_auth/_refresh.py`: refresh sharing (one result per refresh token for 5 seconds,
  across threads).
- `src/seamless_auth/_manifest.py`: parsing, matching, the live and bundled manifest.
- `src/seamless_auth/_cookies.py`, `_jwt.py`, `_jwks.py`: HS256 cookies and service tokens, RS256
  against the API's JWKS.
- `src/seamless_auth/fastapi.py`, `django.py`: the framework bindings. They translate requests and
  responses and nothing else; behaviour lives in the core.
- `tests/`: unit tests against a fake auth API (`httpx2.MockTransport`) and both bindings.
- `conformance/`: the FastAPI and Django reference apps for the conformance suite. Test fixtures.

## Contract

This package bridges to the `seamless-auth-api` contract. Behaviour must match the Node adapters in
`fells-code/seamless-auth-server`, the Go and Rust adapters (`fells-code/seamless-auth-go`,
`fells-code/seamless-auth-rust`), and the conformance contract in `fells-code/seamless-cli`
(`verify/CONFORMANCE.md`). When they disagree, the conformance suite is the arbiter: change the
suite deliberately, never the adapter quietly.

- Keep dependencies minimal (httpx2 and PyJWT). Adopters audit this code; justify every new one in
  `pyproject.toml`.
- Never put `token` or `refreshToken` in a cookie-transport response body.
- Verify every session token against the API's JWKS before issuing a cookie from it.
- Never add a hop-count client IP option. It cannot tell a proxy from a client.
- The default HTTP client follows no redirects: a redirect would carry the service token away.

## Releases

Automated by release-please (`release-please-config.json`, `.github/workflows/release.yml`). Do not
bump the version, edit the changelog, or tag by hand:

- Every push to `main` opens or updates a `chore: release vX.Y.Z` PR. The version and changelog
  come from Conventional Commits since the last release, so the commit type is the release note:
  `fix:` bumps the patch version, `feat:` or a breaking change (`feat!:`, `BREAKING CHANGE:`) the
  minor version while pre-1.0. `ci`, `chore`, `test`, `style` and `build` commits make no release.
- Merging that PR tags `vX.Y.Z`, creates the GitHub release, then checks, builds and publishes the
  package to PyPI through trusted publishing (no token in the repository).

Pre-1.0: a breaking change is a minor bump, and 1.0 is a deliberate decision, not a side effect.
