## What this changes

<!-- What and why. Link the issue if there is one. -->

## How it was tested

- [ ] `python -m ruff check .` and `python -m ruff format --check .`
- [ ] `python -m mypy`
- [ ] `python -m pytest`
- [ ] `python scripts/generate_rules_doc.py --check` (if rules changed)
- [ ] `python -m reposentinel scan .` (no findings)
- [ ] `npm run typecheck && npm run build && npm run e2e` in `frontend/` (if the web interface changed)

## Checklist

- [ ] No real or real-looking secrets; synthetic values are assembled at run time.
- [ ] Finding text does not quote repository content.
- [ ] Wording stays conservative (never "fixed", "resolved" or "secure").
- [ ] Documentation and `CHANGELOG.md` updated if behaviour changed.
