# Suggested Development Commands

## Node.js (Main PromptForge Server)
```bash
# Install dependencies
npm install

# Start the server
npm start

# The server runs on port 3006 (or PORT env variable)
```

## Python/Serena Commands
```bash
# Format code (MUST use before commits)
uv run poe format

# Type checking (MUST pass before commits)
uv run poe type-check

# Run tests
uv run poe test

# Run specific language tests
uv run poe test -m "python or go"

# Lint (check style without fixing)
uv run poe lint

# Start MCP server
uv run serena-mcp-server

# Index project (deprecated but available)
uv run index-project
```

## Git Commands
```bash
# Check status
git status

# View diffs
git diff

# Commit changes
git add .
git commit -m "message"

# View recent commits
git log --oneline -10
```

## System Utilities (Linux)
```bash
# List files
ls -la

# Find files
find . -name "*.js"

# Search in files (use ripgrep)
rg "pattern"

# Navigate directories
cd path/to/dir

# View file contents
cat filename
```