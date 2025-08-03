# Task Completion Checklist

## For JavaScript/Node.js Changes
1. Ensure code follows standard JavaScript conventions
2. Test the server manually: `npm start`
3. Verify OAuth flow works correctly
4. Check for any console errors or warnings
5. Ensure no secrets are exposed in code

## For Python/Serena Changes
1. **Format code**: `uv run poe format`
2. **Type check**: `uv run poe type-check` (MUST pass)
3. **Run tests**: `uv run poe test` (relevant test markers)
4. **Lint check**: `uv run poe lint` (optional but recommended)
5. Verify no breaking changes to existing functionality

## Before Any Commit
1. Review all changes with `git diff`
2. Ensure all formatters and type checkers pass
3. Run relevant tests
4. Write clear, descriptive commit messages
5. Never commit secrets, keys, or sensitive data

## General Quality Checks
- Code is readable and self-documenting
- Functions have single responsibilities
- Error handling is appropriate
- Security best practices followed
- No commented-out code or debug prints