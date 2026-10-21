# Security policy

TreeWard is a best-effort preflight tool. Its pattern-based checks can miss secrets and can produce false positives. Do not treat a clean result as proof that a repository is safe to publish.

## Using TreeWard safely

- Treat any suspected credential as exposed: revoke or rotate it, even if the finding may be a false positive.
- If a credential was committed, remove it from affected Git history as well as the current files.
- Do not paste credentials or private repository contents into public issues.
- Pair TreeWard with your Git host's secret scanning and a history-aware scanner.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository when it is enabled. If private reporting is unavailable, contact a repository maintainer through the contact details on their GitHub profile. Do not publish exploit details in a public issue.
