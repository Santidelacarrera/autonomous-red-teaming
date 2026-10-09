## Summary

<!-- What does this change do and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Security hardening
- [ ] Documentation
- [ ] Refactor / chore

## Security checklist

- [ ] Preserves the simulation-only scope (no real exploitation, apply, or cloud mutation)
- [ ] New config/adapters fail closed
- [ ] No secrets, tokens, or credentials added to the repo
- [ ] New behavior is covered by tests (including fail-closed tests for security controls)

## Verification

- [ ] `make check` passes (ruff, mypy, bandit, pytest)
- [ ] Frontend `npm run lint && npm run typecheck && npm test && npm run build` pass (if touched)
- [ ] `make docker-scan` passes (if Dockerfile/deps touched)

## Notes for reviewers

<!-- Anything reviewers should pay special attention to. -->
