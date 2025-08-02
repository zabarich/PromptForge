# PromptForge MCP Server

Transform natural language prompts into structured XML format using a hybrid MCP (Model Context Protocol) approach.

## Overview

PromptForge is an MCP server that helps convert ambiguous natural language prompts into well-structured XML format. It reduces ambiguity, anchors attention, and improves reliability across LLM interactions by enforcing a consistent prompt structure.

## Connecting to Claude Desktop

### Using Static OAuth Credentials

PromptForge supports static OAuth credentials for easy connection to Claude Desktop:

1. **Open Claude Desktop settings**
2. **Add a custom MCP server**
3. **Enter the following details:**
   - **Server URL:** `https://promptforge-w36c.onrender.com`
   - **OAuth Client ID:** `promptforge-static-client`
   - **OAuth Client Secret:** `promptforge-static-secret-2025`
4. **Click Connect**

Claude will authenticate using the OAuth 2.1 authorization code flow with PKCE. Once connected, you'll have access to the `promptforge_transform` tool.

## How It Works

PromptForge uses a hybrid MCP approach:
1. Receives natural language prompts via HTTP POST
2. Returns transformation instructions and the original prompt
3. Claude (or another LLM) executes the transformation using the provided instructions
4. Result is structured XML following the defined schema

## Quick Start

### Prerequisites
- Node.js 14+ installed
- npm or yarn package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/zabarich/PromptForge.git
cd PromptForge

# Install dependencies
npm install

# Start the server
npm start
```

The server will start on port 3006 (or the PORT environment variable if set).

### Usage

Send a POST request to transform a prompt:

```bash
curl -X POST http://localhost:3006/api/mcp/transform \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "transform",
    "params": {
      "prompt": "create a marketing strategy for a new product"
    },
    "id": 1
  }'
```

## Deployment Guide for Render

### Deploy to Render

1. **Fork or clone this repository** to your GitHub account

2. **Sign in to Render** at https://render.com

3. **Create a new Web Service:**
   - Click "New +" → "Web Service"
   - Connect your GitHub account if not already connected
   - Select the PromptForge repository

4. **Configure the service:**
   - **Name:** promptforge (or your preferred name)
   - **Environment:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Instance Type:** Free (or your preferred tier)

5. **Click "Create Web Service"**

Your PromptForge server will be deployed and accessible at:
`https://[your-service-name].onrender.com/api/mcp/transform`

### Environment Variables

The server automatically uses the PORT environment variable provided by Render. No additional configuration needed.

## Customizing Instructions

The transformation instructions are stored in `promptforge-instructions.xml`. To customize:

1. Edit the XML file to modify transformation rules
2. Update the schema, validation steps, or output format
3. Restart the server to apply changes

### Key sections to customize:

- `<law>` - Core transformation rules
- `<output-format-requirement>` - XML structure template
- `<schema>` - Allowed XML tags
- `<validation-step>` - Validation requirements

## API Reference

### MCP Protocol Endpoint

#### POST /mcp

The main MCP endpoint that handles all JSON-RPC methods following the Model Context Protocol.

**Available Methods:**

1. **initialize** - Initialize MCP connection
   ```json
   {
     "jsonrpc": "2.0",
     "method": "initialize",
     "id": 1
   }
   ```

2. **tools/list** - List available tools
   ```json
   {
     "jsonrpc": "2.0",
     "method": "tools/list",
     "id": 2
   }
   ```

3. **tools/call** - Execute the PromptForge transformation
   ```json
   {
     "jsonrpc": "2.0",
     "method": "tools/call",
     "params": {
       "name": "promptforge_transform",
       "arguments": {
         "prompt": "your natural language prompt here"
       }
     },
     "id": 3
   }
   ```

### Legacy Endpoint (for backward compatibility)

#### POST /api/mcp/transform

The original endpoint is maintained for backward compatibility.

**Request Body:**
```json
{
  "jsonrpc": "2.0",
  "method": "transform",
  "params": {
    "prompt": "your natural language prompt here"
  },
  "id": 1
}
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.