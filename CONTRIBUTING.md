# Contributing

Thanks for helping make repository preflight checks more useful and less noisy.

## Before opening a pull request

- Explain the problem and include a small, non-sensitive reproduction when possible.
- Keep new rules specific and describe their known false-positive cases.
- Never commit real credentials, even when using them as an example. Use obvious placeholders.
- Keep runtime dependencies at zero unless a dependency adds clear value.
- Update the README when user-visible behavior, rules, or configuration changes.

## Development setup

Use Python 3.11 or newer. From the repository root:

~~~console
python -m pip install .
python -m treeward --help
~~~

Please include the command and Python version you used when reporting a behavior that differs by platform. Pull requests should describe manual checks performed and any remaining limitations.

## Reporting a false positive

Open an issue with the rule ID, a sanitized example, and the file type. Do not include real credentials or private repository data. If a value may be a real credential, revoke it first and use the private reporting process in [SECURITY.md](SECURITY.md).
