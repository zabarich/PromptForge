const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static OAuth credentials
const STATIC_CLIENT_ID = 'promptforge-static-client';
const STATIC_CLIENT_SECRET = 'promptforge-static-secret-2025';

// In-memory storage for tokens and auth codes (MVP - not for production)
const authCodes = new Map();
const accessTokens = new Map();

// Generate random token
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

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

// Bearer token validation middleware
function validateBearerToken(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Missing or invalid authorization header'
    }).set('WWW-Authenticate', 'Bearer realm="PromptForge", error="invalid_token"');
  }
  
  const token = authHeader.substring(7);
  const tokenData = accessTokens.get(token);
  
  if (!tokenData || tokenData.expires_at < Date.now()) {
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Invalid or expired token'
    }).set('WWW-Authenticate', 'Bearer realm="PromptForge", error="invalid_token"');
  }
  
  req.tokenData = tokenData;
  next();
}

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
 * OAuth2 metadata endpoint - tells Claude where to find OAuth endpoints
 */
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const baseUrl = `https://${req.get('host')}`;
  
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    registration_endpoint: `${baseUrl}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    scopes_supported: ['mcp:access']
  });
});

/**
 * OAuth2 authorization endpoint
 */
app.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, state, code_challenge, code_challenge_method } = req.query;
  
  console.log('[OAuth Authorize] Request:', { client_id, redirect_uri, response_type, state });
  
  // Validate client_id
  if (client_id !== STATIC_CLIENT_ID) {
    return res.status(400).send('Invalid client_id');
  }
  
  // Validate response_type
  if (response_type !== 'code') {
    return res.status(400).send('Unsupported response_type');
  }
  
  // Generate authorization code
  const code = generateToken();
  authCodes.set(code, {
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    created_at: Date.now(),
    expires_at: Date.now() + 600000 // 10 minutes
  });
  
  // Redirect back with code
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) {
    redirectUrl.searchParams.set('state', state);
  }
  
  res.redirect(redirectUrl.toString());
});

/**
 * OAuth2 token endpoint
 */
app.post('/token', (req, res) => {
  const { grant_type, code, client_id, client_secret, code_verifier } = req.body;
  
  console.log('[OAuth Token] Request:', { grant_type, client_id, has_code: !!code });
  
  // Validate grant type
  if (grant_type !== 'authorization_code') {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only authorization_code grant type is supported'
    });
  }
  
  // Validate client credentials
  if (client_id !== STATIC_CLIENT_ID || client_secret !== STATIC_CLIENT_SECRET) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid client credentials'
    });
  }
  
  // Validate authorization code
  const codeData = authCodes.get(code);
  if (!codeData || codeData.expires_at < Date.now()) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid or expired authorization code'
    });
  }
  
  // Validate PKCE if present
  if (codeData.code_challenge && codeData.code_challenge_method === 'S256') {
    const verifier = crypto.createHash('sha256').update(code_verifier).digest('base64url');
    if (verifier !== codeData.code_challenge) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid code verifier'
      });
    }
  }
  
  // Remove used authorization code
  authCodes.delete(code);
  
  // Generate access token
  const accessToken = generateToken();
  const expiresIn = 1800; // 30 minutes
  
  accessTokens.set(accessToken, {
    client_id,
    scope: 'mcp:access',
    created_at: Date.now(),
    expires_at: Date.now() + (expiresIn * 1000)
  });
  
  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: expiresIn,
    scope: 'mcp:access'
  });
});

/**
 * OAuth2 Dynamic Client Registration endpoint
 * Returns static credentials for PromptForge
 */
app.post('/register', (req, res) => {
  console.log('[OAuth Register] Returning static credentials');
  
  res.json({
    client_id: STATIC_CLIENT_ID,
    client_secret: STATIC_CLIENT_SECRET,
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_post',
    scope: 'mcp:access',
    redirect_uris: req.body.redirect_uris || ['https://claude.ai/api/mcp/auth_callback']
  });
});

/**
 * Main MCP endpoint at root path for Claude Chat
 * POST / - handles JSON-RPC methods
 * GET / - handles SSE connections
 */
app.post('/', validateBearerToken, (req, res) => {
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
app.post('/mcp', validateBearerToken, (req, res) => {
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
app.post('/api/mcp/transform', validateBearerToken, (req, res) => {
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