# Project Structure

## Root Directory
```
SUPERPROMPT2.0/
├── server.js                    # Main Express server
├── package.json                 # Node.js dependencies
├── package-lock.json           # Dependency lock file
├── promptforge-instructions.xml # Transformation rules
├── README.md                   # Project documentation
├── LICENSE                     # MIT License
├── .gitignore                  # Git ignore rules
├── .serena/                    # Serena configuration/memories
├── .claude/                    # Claude-specific config
└── serena/                     # Serena MCP server (Python)
    ├── src/                    # Source code
    │   ├── serena/            # Main agent code
    │   │   ├── agent.py       # Core agent orchestrator
    │   │   ├── tools/         # Tool implementations
    │   │   └── config/        # Configuration system
    │   └── solidlsp/          # Language server wrapper
    │       └── language_servers/ # Per-language support
    ├── test/                   # Test suites
    ├── docs/                   # Documentation
    ├── scripts/                # Utility scripts
    ├── pyproject.toml         # Python project config
    ├── uv.lock                # Python dependency lock
    ├── CLAUDE.md              # Claude-specific instructions
    └── README.md              # Serena documentation
```

## Key Components
- **PromptForge Server**: Node.js/Express HTTP API
- **Serena Agent**: Python-based coding assistant with LSP support
- **OAuth Integration**: Static credentials for Claude Desktop
- **MCP Protocol**: Enables tool access for AI agents