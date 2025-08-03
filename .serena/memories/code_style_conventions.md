# Code Style and Conventions

## JavaScript (Main Server)
- **Style**: Standard JavaScript conventions
- **Indentation**: 2 spaces
- **Variables**: Descriptive names, camelCase
- **Constants**: UPPER_SNAKE_CASE
- **Functions**: Clear, descriptive names
- **Comments**: Minimal, code should be self-documenting

## Python (Serena)
- **Style Guide**: PEP 8 compliant
- **Formatting**: Black + Ruff (strict enforcement)
- **Type Hints**: Required, validated with mypy
- **Indentation**: 4 spaces
- **Naming Conventions**:
  - Functions/variables: snake_case
  - Classes: PascalCase
  - Constants: UPPER_SNAKE_CASE
- **Import Order**: Standard library, third-party, local
- **Documentation**: Docstrings for public APIs

## General Conventions
- No emojis in code unless explicitly requested
- Security first: Never expose secrets or keys
- Test-driven development approach
- Clear separation of concerns
- Modular, reusable components