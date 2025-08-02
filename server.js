const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
app.use(express.json());

// Add CORS middleware for Claude Chat
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

const PROMPTFORGE_INSTRUCTIONS = fs.readFileSync('./promptforge-instructions.xml', 'utf-8');

// Define the PromptForge tool schema for MCP
const PROMPTFORGE_TOOL = {
  name: 'promptforge_transform',
  description: 'Transform natural language prompts into structured XML format',
  inputSchema: {
    type: 'object',
    properties: {
      prompt: {
        type: 'string',
        description: 'The natural language prompt to transform into structured XML'
      }
    },
    required: ['prompt']
  }
};

/**
 * OAuth2 Dynamic Client Registration endpoint
 * Required by Claude Chat for authentication
 */
app.post('/register', (req, res) => {
  console.log('[OAuth Register] Client registration request');
  
  // Return a mock client registration response
  res.json({
    client_id: 'promptforge-client-' + Date.now(),
    client_secret: 'mock-secret-' + Math.random().toString(36),
    grant_types: req.body.grant_types || ['authorization_code', 'refresh_token'],
    response_types: req.body.response_types || ['code'],
    token_endpoint_auth_method: 'client_secret_post',
    scope: req.body.scope || 'claudeai',
    redirect_uris: req.body.redirect_uris || ['https://claude.ai/api/mcp/auth_callback']
  });
});

/**
 * Main MCP endpoint at root path for Claude Chat
 * POST / - handles JSON-RPC methods
 * GET / - handles SSE connections
 */
app.post('/', (req, res) => {
  try {
    const { method, params, id } = req.body;
    
    // Log incoming requests for debugging
    console.log(`[MCP Request] Method: ${method}, ID: ${id}`);
    
    // Handle MCP methods
    handleMCPRequest(req, res);
  } catch (error) {
    console.error('MCP endpoint error:', error);
    return res.json({
      jsonrpc: '2.0',
      id: req.body?.id || null,
      error: {
        code: -32603,
        message: 'Internal error',
        data: { details: error.message }
      }
    });
  }
});

// SSE endpoint for streaming
app.get('/', (req, res) => {
  console.log('[SSE Connection] Client connected for streaming');
  
  // Set SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });
  
  // Send initial connection message
  res.write('data: {"type":"connection","status":"connected"}\n\n');
  
  // Keep connection alive
  const keepAlive = setInterval(() => {
    res.write(':keep-alive\n\n');
  }, 30000);
  
  // Clean up on disconnect
  req.on('close', () => {
    clearInterval(keepAlive);
    console.log('[SSE Connection] Client disconnected');
  });
});

/**
 * Main MCP endpoint that handles all JSON-RPC methods
 * Also available at /mcp for backward compatibility
 */
app.post('/mcp', (req, res) => {
  handleMCPRequest(req, res);
});

// Extracted MCP request handler
function handleMCPRequest(req, res) {
  try {
    const { method, params, id } = req.body;
    
    // Log incoming requests for debugging
    console.log(`[MCP Request] Method: ${method}, ID: ${id}`);
    
    switch (method) {
      case 'initialize':
        // Initialize the MCP connection
        return res.json({
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: {
              tools: {}
            },
            serverInfo: {
              name: 'PromptForge',
              version: '1.0.0'
            }
          }
        });

      case 'tools/list':
        // List available tools
        return res.json({
          jsonrpc: '2.0',
          id,
          result: {
            tools: [PROMPTFORGE_TOOL]
          }
        });

      case 'tools/call':
        // Execute tool call
        const { name: toolName, arguments: args } = params || {};
        
        if (!toolName) {
          return res.json({
            jsonrpc: '2.0',
            id,
            error: {
              code: -32602,
              message: 'Invalid parameters',
              data: { details: 'Tool name is required' }
            }
          });
        }

        if (toolName !== 'promptforge_transform') {
          return res.json({
            jsonrpc: '2.0',
            id,
            error: {
              code: -32601,
              message: 'Method not found',
              data: { details: `Tool "${toolName}" not found` }
            }
          });
        }

        const prompt = args?.prompt;
        if (!prompt) {
          return res.json({
            jsonrpc: '2.0',
            id,
            error: {
              code: -32602,
              message: 'Invalid parameters',
              data: { details: 'Prompt is required' }
            }
          });
        }

        // Return the transformation instructions for Claude to execute
        const content = [
          {
            type: 'text',
            text: `${PROMPTFORGE_INSTRUCTIONS}\n\n---\n\nUser's prompt to transform:\n${prompt}\n\n---\n\nTransform the above user prompt according to the PromptForge instructions and return the result in the specified XML format.`
          }
        ];

        return res.json({
          jsonrpc: '2.0',
          id,
          result: {
            content
          }
        });

      default:
        // Method not found
        return res.json({
          jsonrpc: '2.0',
          id,
          error: {
            code: -32601,
            message: 'Method not found',
            data: { details: `Method "${method}" is not supported` }
          }
        });
    }
  } catch (error) {
    console.error('MCP endpoint error:', error);
    return res.json({
      jsonrpc: '2.0',
      id: req.body?.id || null,
      error: {
        code: -32603,
        message: 'Internal error',
        data: { details: error.message }
      }
    });
  }
}

// Keep the old endpoint for backward compatibility
app.post('/api/mcp/transform', (req, res) => {
  const prompt = req.body.prompt || (req.body.params && req.body.params.prompt);
  
  if (!prompt) {
    return res.status(400).json({ error: 'No prompt provided' });
  }

  if (req.body.jsonrpc) {
    res.json({
      jsonrpc: '2.0',
      result: {
        action: 'execute_transformation',
        system_prompt: PROMPTFORGE_INSTRUCTIONS,
        user_prompt: prompt,
        directive: 'Transform the user_prompt using the system_prompt instructions and return the result in structured XML format.'
      },
      id: req.body.id
    });
  } else {
    res.json({
      action: 'execute_transformation',
      system_prompt: PROMPTFORGE_INSTRUCTIONS,
      user_prompt: prompt,
      directive: 'Transform the user_prompt using the system_prompt instructions and return the result in structured XML format.'
    });
  }
});

// Add catch-all route to log any unhandled requests
app.use('*', (req, res) => {
  console.log(`[Unhandled Request] ${req.method} ${req.originalUrl}`);
  console.log(`[Headers]`, JSON.stringify(req.headers, null, 2));
  console.log(`[Body]`, JSON.stringify(req.body, null, 2));
  
  res.status(404).json({
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.originalUrl}`,
    hint: 'MCP endpoint is at /mcp'
  });
});

const PORT = process.env.PORT || 3006;
app.listen(PORT, () => {
  console.log(`PromptForge MCP server running on port ${PORT}`);
  console.log(`MCP endpoint: http://localhost:${PORT}/mcp`);
});