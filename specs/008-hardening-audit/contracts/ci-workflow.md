# Contract: CI Workflow

**Covers**: FR-031..FR-035, SC-010, SC-011 | Research R15, R16

## File

`.github/workflows/ci.yml`, written in the restricted YAML subset the policy checker reads
(block style only; no anchors, aliases, tags, flow collections or `---`).

## Shape

```yaml
name: ci
on:
  push:
  pull_request:
  workflow_dispatch:
  schedule:
    - cron: "17 4 * * 1"
permissions:
  contents: read
defaults:
  run:
    shell: bash
env:
  ARCH_SNAPSHOT: "UNRESOLVED"        # YYYY/MM/DD of archive.archlinux.org, set by a maintainer (quickstart CI-0)
  CARGO_DENY_VERSION: "0.20.2"
  CARGO_AUDIT_VERSION: "0.22.2"
  CARGO_TERM_COLOR: never
jobs:
  gate:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    container:
      image: archlinux@sha256:0000000000000000000000000000000000000000000000000000000000000000
    steps:
      - name: refuse unresolved pins
        run: '[[ "$ARCH_SNAPSHOT" =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}$ ]] || { echo "refuse: ARCH_SNAPSHOT unresolved" >&2; exit 1; }'
      - name: packages from dated snapshot
        run: write /etc/pacman.d/mirrorlist = Server = https://archive.archlinux.org/repos/${ARCH_SNAPSHOT}/$repo/os/$arch ; pacman -Syyuu --noconfirm git rust python libxml2 ...
      - name: checkout (anonymous, no credentials stored)
        run: git init -q . ; git fetch --depth=1 --no-tags "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY.git" "$GITHUB_SHA" ; git checkout -q FETCH_HEAD
      - name: tools
        run: cargo install --locked cargo-deny@"$CARGO_DENY_VERSION" cargo-audit@"$CARGO_AUDIT_VERSION"
      - name: fetch inputs
        run: scripts/gate.sh --fetch
      - name: gate
        run: scripts/gate.sh
  android:     # same container, snapshot, checkout and tools; runs android/verify.sh
  packaging:   # same container; creates user `builder`; runs packaging/verify.sh --fetch then packaging/verify.sh as builder
```

The "refuse unresolved pins" step is the same in every job. With the all-zero digest the
runner already fails while pulling the container, before any step; the step additionally
catches an unresolved `ARCH_SNAPSHOT` once the digest is set. Either way the job fails closed
and never runs on an unpinned image or a live mirror. Exact package lists are set at
task time from the tools each verify script checks for (`android/verify.sh`: cargo, python3,
xmllint, cargo-deny, cargo-audit; `packaging/verify.sh`: the tools listed in 006
contracts/verify.md, including `makepkg`, `namcap`, `systemd-analyze`).

## Policy rules (scripts/check_workflow.py)

| Rule | Requirement | Negative fixture |
|------|-------------|------------------|
| W1 | parses as the restricted subset; top-level keys only `name`, `on`, `permissions`, `defaults`, `env`, `jobs` | anchor/alias, flow mapping, extra top-level key |
| W2 | triggers ⊆ {`push`, `pull_request`, `workflow_dispatch`, `schedule`} and all four present; schedule exactly one weekly cron | `pull_request_target`, `workflow_run`, `issue_comment`, missing schedule |
| W3 | top-level `permissions` is exactly `{contents: read}`; no job-level `permissions` other than identical; no `write`, `write-all`, `read-all` anywhere | `contents: write`, `id-token: write`, `permissions: write-all` |
| W4 | no `secrets.` / `secrets[`, no `github.token`, no `GITHUB_TOKEN`, no `environment:` key, no `ACTIONS_RUNTIME_TOKEN`/`ACTIONS_ID_TOKEN` | each one |
| W5 | every `uses:` (if any) is `owner/repo[/path]@<40 hex>`; `docker://` uses need `@sha256:<64 hex>`; local `./` actions forbidden | `@v4`, `@main`, short SHA |
| W6 | every `image:` and `container:` value is `name@sha256:<64 hex>`; the all-zero digest is reported `PENDING [CI]` but not a failure | `archlinux:latest`, `archlinux:base` |
| W7 | no step stores credentials: forbid `persist-credentials: true`, `git config ... credential`, `http.extraheader`, tokens in URLs (`https://.*@`); if `actions/checkout` is ever used it must set `persist-credentials: false` | each one |
| W8 | no publish/push/tag/release/deploy/comment/upload/cache-write step: forbid `git push`, `git tag`, `gh `, `cargo publish`, `docker push`, `docker login`, `twine`, `npm publish`, `upload-artifact`, `actions/cache`, `/releases`, `curl -X POST`/`PUT`/`PATCH`/`DELETE`, `--upload-file` | each one |
| W9 | every job has integer `timeout-minutes` in 1..=120 | missing, 0, 1000 |
| W10 | `scripts/gate.sh`, `android/verify.sh` and `packaging/verify.sh` are each invoked in some job; no `|| true`, `continue-on-error`, `set +e` around them | missing call, `continue-on-error: true`, `|| true` |
| W11 | tool installs pinned: every `cargo install` has `--locked` and an exact `@X.Y.Z` (or `--version X.Y.Z` via a pinned env value); no `rustup`, `curl ... | sh`, `wget ... | sh`, `pip install`, `npm install`, `apt-get install` without `=version` | each one |
| W12 | pacman uses only `https://archive.archlinux.org/repos/<date or ${ARCH_SNAPSHOT}>/`; `ARCH_SNAPSHOT` is `YYYY/MM/DD` or `UNRESOLVED` (reported `PENDING [CI]`) | `mirrors.kernel.org`, `pacman-mirrors`, `reflector` |
| W13 | the "refuse unresolved pins" step is the first step of every job | missing or moved |
| W14 | `runs-on` is a GitHub-hosted label (`ubuntu-*`); no `self-hosted` | `self-hosted` |

CLI: `python3 scripts/check_workflow.py [.github/workflows/ci.yml]`; prints `PASS` (plus one
`PENDING [CI] <pin>` line per unresolved pin) or one `FAIL Wn: <detail>` per violation; exit 0
(pass, pending allowed) / 1 (fail) / 64 (usage). Negative tests:
`scripts/tests/test_check_workflow.py` generates one mutated copy per fixture row from the real
workflow file and asserts `FAIL Wn` with the expected rule.

## Run-time guarantees [CI]

- Fork PRs run with `pull_request`: read-only token, no secrets (GitHub platform rule),
  verified by SC-011 on a real run.
- Any non-zero exit, including verify-script status 2 (incomplete), fails the job (bash default
  `-e` with `pipefail` on GitHub's `bash` shell; W10 forbids masking).
- Scheduled runs use the same jobs and permissions; they never open issues or publish.
