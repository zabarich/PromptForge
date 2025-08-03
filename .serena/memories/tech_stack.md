# Technology Stack

## Main PromptForge Server
- **Runtime**: Node.js 14+
- **Framework**: Express.js ^4.18.2
- **Language**: JavaScript
- **Package Manager**: npm
- **Deployment**: Render (cloud platform)

## Serena Integration (subdirectory)
- **Language**: Python 3.11
- **Package Manager**: uv (modern Python dependency manager)
- **Key Dependencies**:
  - mcp==1.12.3 (Model Context Protocol)
  - pyright (type checking)
  - flask (web framework)
  - pydantic (data validation)
  - anthropic SDK
  - Various language server integrations

## Development Tools
- Git for version control
- npm for Node.js package management
- uv for Python package management
- pytest for Python testing
- mypy for Python type checking
- black + ruff for Python formatting