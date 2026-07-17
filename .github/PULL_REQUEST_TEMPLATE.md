## Summary

What does this change do, and why?

Closes #<!-- issue number, if any -->

## Changes

- …

## How verified

The commands you ran and what you observed — not "should work."

```
ruff check .
ruff format --check .
pytest
```

<!-- Paste the relevant output, and describe any manual verification (e.g. drove the
     signing flow end-to-end). -->

## Checklist

- [ ] `ruff check .` and `ruff format --check .` pass.
- [ ] `pytest` passes (with `SIGN_SECRET` set).
- [ ] Tests added/updated for the behavior change; a bug fix includes a regression test.
- [ ] Docs and `CHANGELOG.md` updated in this PR if the change is user-facing.
- [ ] No secrets, real customer data, or hardcoded identity (domains/emails/company
      names) in the diff — those are configuration.
- [ ] No new coupling to external/private infrastructure; the package stays standalone.
- [ ] Security-relevant behavior keeps its module's threat-model docstring accurate, and
      SECURITY.md is updated if a documented defense changed.
