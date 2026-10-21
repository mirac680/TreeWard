# TreeWard

**A private, local-first preflight check before you publish a Git repository.**

TreeWard looks for common accidental exposures and a few easy-to-miss release basics: credential-shaped values, private-key markers, sensitive file names, oversized files, and missing README or license files. It runs on your machine, has no runtime dependencies, and never prints matched secret values.

> TreeWard is a quick preflight, not a complete security audit. It does not inspect the Git index or history.

## Why TreeWard?

Before making a repository public, it is easy to overlook a local <code>.env</code>, a copied key, or a large generated file. TreeWard gives contributors a fast, repeatable check they can run before a push or in continuous integration.

- **Private by default:** scans the local working tree and makes no network requests.
- **Actionable output:** every finding has a rule, location, severity, and suggested fix.
- **Automation-friendly:** readable terminal output, JSON, and SARIF 2.1.0.
- **No runtime dependencies:** Python 3.11 or newer and Git are enough.
- **Careful with secrets:** reports do not contain the matched value.

## Pre-commit hook

After installing TreeWard in the environment used by your hooks, add this local hook to <code>.pre-commit-config.yaml</code>:

~~~yaml
repos:
  - repo: local
    hooks:
      - id: treeward
        name: TreeWard
        entry: treeward
        language: system
        pass_filenames: false
~~~

Install the hook with <code>pre-commit install</code>. The hook scans the working tree on each commit attempt.

## Quick start

From a checkout of this project:

~~~console
python -m pip install .
treeward .
~~~

You can also run it without installing the command entry point:

~~~console
python -m treeward .
~~~

Run it from any directory inside the repository. TreeWard finds the Git root and checks tracked files plus non-ignored untracked files in the working tree.

## Examples

~~~console
# Human-readable report (default)
treeward

# Machine-readable report
treeward . --format json

# SARIF report for code-scanning integrations
treeward . --format sarif --output treeward.sarif

# Fail CI on medium or higher findings
treeward . --fail-on medium

# Check a larger text-file limit
treeward . --max-file-size-mb 10
~~~

<code>--fail-on</code> accepts <code>high</code>, <code>medium</code>, <code>low</code>, or <code>never</code>. The default is <code>high</code>. A high-severity finding exits with status 1; a scan/configuration error exits with status 2. The report is still written when findings cause a non-zero exit.

## GitHub Actions

TreeWard includes a composite GitHub Action. After publishing this repository and creating a release tag, use it in your workflow:

~~~yaml
name: Repository preflight

on:
  pull_request:

permissions:
  contents: read

jobs:
  treeward:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: <owner>/treeward@v0.1.0
        with:
          fail-on: medium
~~~

Replace <code>&lt;owner&gt;</code> with the account that hosts your copy. The action prints readable findings in the job log and writes <code>treeward.sarif</code> in the workspace, including when the severity threshold fails; set <code>report-path</code> to change it. Pin the action to a reviewed release or commit for repeatable CI. The SARIF file is ready for a code-scanning upload step if you enable one.

The action reads <code>.treeward.toml</code> from the repository root. Leave <code>fail-on</code> and <code>max-file-size-mb</code> unset to use the repository config; pass either input to override it.

This repository includes a self-check workflow at <code>.github/workflows/treeward.yml</code>. It runs the local action on pushes to <code>main</code> and on pull requests.

## What it checks

| Rule | Severity | Check |
| --- | --- | --- |
| <code>TW001</code> | High | Private-key PEM markers |
| <code>TW002</code> | High | Selected GitHub, Slack, Google, and Stripe credential patterns |
| <code>TW003</code> | Medium | Non-placeholder values assigned to credential-like settings such as <code>password</code>, <code>api_key</code>, or <code>client_secret</code> |
| <code>TW004</code> | High | Names commonly used for credentials, including <code>.env</code>, private-key files, and cloud credentials |
| <code>TW005</code> | Medium | Files larger than the configured size limit |
| <code>TW006</code> | Medium | AWS access key identifier (the identifier alone is not a secret credential) |
| <code>TW101</code> | Info | Missing top-level README |
| <code>TW102</code> | Info | Missing top-level license |

Pattern rules are intentionally transparent and small. They can miss credentials and may flag values that only look sensitive. The AWS identifier rule is medium severity because an access key ID alone does not grant access. Review each finding before acting.

## Configuration

Create <code>.treeward.toml</code> at your repository root:

~~~toml
[scan]
max_file_size_mb = 2
exclude = [
  "docs/generated/**",
]

fail_on = "high"
~~~

<code>max_file_size_mb</code> accepts values greater than 0 and up to 100 MiB. <code>fail_on</code> accepts <code>high</code>, <code>medium</code>, <code>low</code>, or <code>never</code>. <code>exclude</code> uses path globs relative to the repository root. Excluded paths are not read and do not count toward README/license checks. Avoid broad exclusions: they can hide a real finding. Use <code>--config path/to/file.toml</code> to choose a different config file.

## Scan scope and limitations

- Scans Git-tracked files and non-ignored untracked files in the current working tree. Ignored, excluded, and historical versions are not read.
- Does not inspect the Git index separately. If staged content differs from the current working tree, that staged snapshot is not checked.
- Does not scan Git history. A credential removed from the current files may still exist in old commits. Use a history-aware secret scanner and rotate any exposed credential.
- Skips symlinks, binary files, unreadable files, and files larger than the configured limit.
- Checks UTF-8 text only. It does not execute code, contact providers, or verify whether a detected credential is active.
- A clean report is not proof that a repository is safe to publish.

For wider coverage, pair this preflight with your Git host's secret scanning and a dedicated history-aware scanner.

## Development

~~~console
python -m pip install .
python -m treeward --help
~~~

The implementation uses the Python standard library at runtime. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution notes and [SECURITY.md](SECURITY.md) for responsible disclosure.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

TreeWard is distributed under the MIT License. See [LICENSE](LICENSE).
