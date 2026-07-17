---
name: Good first issue
about: A small, well-scoped task for a first-time contributor (maintainers — use this to propose one)
title: "[Good first issue] "
labels: "good first issue"
assignees: ""
---

<!--
This template is for maintainers to write up small, self-contained tasks that are a
friendly on-ramp for someone contributing to Lifted Sign for the first time.

New here and looking for something to work on? Browse the open ones:
https://github.com/LiftedHoldings/lifted-sign/labels/good%20first%20issue
Comment to claim one before you start so two people don't duplicate work.
-->

## The task

A clear, one-paragraph description of what needs to change and why. Keep it to a single,
self-contained outcome.

## Why it's a good first issue

- [ ] Scoped to one or a few files.
- [ ] Doesn't require deep knowledge of the whole codebase.
- [ ] Has a clear definition of done (below).
- [ ] No new external service or private-infra dependency (see [CONTRIBUTING.md](../../CONTRIBUTING.md)).

## Where to look

Files, functions, or pages likely involved — e.g. `sign/…`, `web/…`, or `docs/…`. Point
newcomers at the right place so they don't have to hunt.

## Definition of done

- [ ] Behavior/change described above is implemented.
- [ ] `pytest -q` passes and `ruff check sign tests` is clean.
- [ ] A test covers the change (if it's code, not docs).
- [ ] Docs updated if user-facing.

## Getting started

New contributors: [`CONTRIBUTING.md`](../../CONTRIBUTING.md) walks through a dev setup
(`pip install -e '.[dev]'`, set `SIGN_SECRET`, `python -m sign`). Ask questions right
here on the issue — we're happy to help you land your first PR.
