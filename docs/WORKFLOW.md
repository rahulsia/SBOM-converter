# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT

# SBOM Converter CI / Security Workflow

The repository workflow is defined in `.github/workflows/security.yml` and runs for
pull requests targeting `main`, plus manual `workflow_dispatch` runs.

## Workflow sequence

```text
Pull Request / Manual Run
        |
        +--> Free automated PR review
        |      Ruff + Reviewdog
        |
        +--> Python security
        |      pytest
        |      Bandit
        |      pip-audit
        |
        +--> Semgrep
        |
        +--> Gitleaks
        |
        +--> Trivy
        |      filesystem
        |      container image
        |
        +--> Hadolint
        |
        '--> GitHub checks / PR status
```

## Jobs

### 1. Free automated PR review

Runner: `ubuntu-latest`

Tools:

- Ruff
- Reviewdog

Ruff output is converted to reviewdog's RDJSON format and reported as GitHub PR
review comments for added/changed lines.

### 2. Python SAST and dependency audit

Runner: `ubuntu-latest`

Runs:

```bash
pytest -q
bandit -r src -ll -ii
pip-audit
```

### 3. Semgrep SAST

Runs Semgrep Community Edition using:

```text
p/python
p/security-audit
```

### 4. Secret scanning

Gitleaks scans the repository history/worktree for committed secrets.

### 5. Filesystem and container scanning

Trivy scans:

```text
Repository filesystem
Docker image built from Dockerfile
```

High and critical vulnerabilities are configured to fail this job when they are fixed
or otherwise detected according to the configured Trivy policy.

### 6. Dockerfile linting

Hadolint checks the Dockerfile with a warning-level failure threshold.

## Permissions

The workflow uses:

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write
```

The pull-request write permission is required for Reviewdog to publish review comments.

## Runner and network behavior

The security workflow uses GitHub-hosted `ubuntu-latest` runners. External HTTPS
providers such as OSV.dev and NVD/NIST can therefore be reached from the workflow
environment when a job explicitly invokes the converter's vulnerability scan.

The normal conversion path does not contact OSV or NVD.

## Local reproduction

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
pytest -q
bandit -r src -ll -ii
pip-audit
ruff check src tests
```

Container scanning and the GitHub PR review comment integration are repository-CI
concerns.

## Important security behavior

OSV and NVD are vulnerability intelligence sources. A vulnerability match does not
automatically establish product exploitability.

The converter keeps vulnerability discovery separate from contextual VEX assessment:

```text
OSV / NVD finding
      |
      +--> VEX exists --> preserve the contextual status
      |
      '--> no VEX -----> unassessed / under investigation
```
