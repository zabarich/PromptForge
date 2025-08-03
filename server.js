const express = require('express');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Auth0 configuration
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN || 'dev-xzj81p1mmm7ek4m5.uk.auth0.com';
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || 'https://promptforge-w36c.onrender.com';

// Auth0 Management API configuration for Dynamic Client Registration
const AUTH0_MANAGEMENT_DOMAIN = process.env.AUTH0_MANAGEMENT_DOMAIN || AUTH0_DOMAIN;
const AUTH0_MANAGEMENT_CLIENT_ID = process.env.AUTH0_MANAGEMENT_CLIENT_ID;
const AUTH0_MANAGEMENT_CLIENT_SECRET = process.env.AUTH0_MANAGEMENT_CLIENT_SECRET;

// Create JWKS client for Auth0
const jwksClient = jwksRsa({
  jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`,
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5
});

// Add CORS middleware for Claude Chat
app.use((req, res, next) => {
  // Enhanced CORS logging
  console.log(`[CORS] ${req.method} ${req.path} from origin:`, req.headers.origin || 'no-origin');
  
  res.header('Access-Control-Allow-Origin', 'https://claude.ai');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    console.log('[CORS] Preflight request from:', req.headers.origin, 'for:', req.path);
    return res.sendStatus(200);
  }
  
  next();
});

let PROMPTFORGE_INSTRUCTIONS;
try {
  PROMPTFORGE_INSTRUCTIONS = fs.readFileSync('./promptforge-instructions.xml', 'utf-8');
} catch (error) {
  console.error('Failed to load promptforge-instructions.xml:', error.message);
  PROMPTFORGE_INSTRUCTIONS = 'Error: Unable to load transformation instructions';
}

// JWT validation middleware for Auth0
async function validateAuth0Token(req, res, next) {
  // CRITICAL: Don't try to set headers if they're already sent (e.g., for SSE)
  if (res.headersSent) {
    console.log('[AUTH] Headers already sent, skipping auth validation');
    return next();
  }
  
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // Only set status and headers if they haven't been sent
    if (!res.headersSent) {
      res.status(401);
      res.set('WWW-Authenticate', 'Bearer realm="PromptForge"');
      return res.json({
        error: 'unauthorized',
        error_description: 'Missing or invalid authorization header'
      });
    }
    return;
  }
  
  const token = authHeader.substring(7);
  
  try {
    // Decode token to get the key ID
    const decoded = jwt.decode(token, { complete: true });
    
    if (!decoded || !decoded.header || !decoded.header.kid) {
      throw new Error('Invalid token structure');
    }
    
    // Get the signing key from Auth0
    let signingKey;
    try {
      const key = await jwksClient.getSigningKey(decoded.header.kid);
      signingKey = key.getPublicKey();
    } catch (keyError) {
      console.error('Failed to get signing key:', keyError.message);
      throw new Error('Unable to verify token signature');
    }
    
    // Verify the token
    const verified = jwt.verify(token, signingKey, {
      audience: AUTH0_AUDIENCE,
      issuer: `https://${AUTH0_DOMAIN}/`,
      algorithms: ['RS256']
    });
    
    req.user = verified;
    next();
  } catch (error) {
    console.error('Token validation error:', error.message);
    // Only send response if headers haven't been sent
    if (!res.headersSent) {
      res.status(401);
      res.set('WWW-Authenticate', 'Bearer realm="PromptForge", error="invalid_token"');
      return res.json({
        error: 'unauthorized',
        error_description: 'Invalid or expired token'
      });
    }
  }
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

// Add root info endpoint for MCP capabilities
app.get('/info', (req, res) => {
  console.log('[INFO] Request received');
  res.json({
    name: 'PromptForge MCP Server',
    version: '1.0.0',
    authentication: {
      type: 'oauth2',
      discovery: '/.well-known/oauth-authorization-server'
    },
    capabilities: {
      tools: true,
      streaming: true
    }
  });
});

/**
 * OAuth2 metadata endpoint - points to Auth0
 * MUST be before any auth middleware
 */
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  console.log('[OAUTH-METADATA] ============================================');
  console.log('[OAUTH-METADATA] Request received at:', new Date().toISOString());
  console.log('[OAUTH-METADATA] Headers:', JSON.stringify(req.headers, null, 2));
  console.log('[OAUTH-METADATA] User-Agent:', req.headers['user-agent']);
  console.log('[OAUTH-METADATA] Origin:', req.headers.origin);
  console.log('[OAUTH-METADATA] Host:', req.get('host'));
  
  const baseUrl = `https://${req.get('host')}`;
  
  const metadata = {
    issuer: `https://${AUTH0_DOMAIN}/`,
    authorization_endpoint: `${baseUrl}/authorize`, // Use our proxy to ensure correct client_id
    token_endpoint: `https://${AUTH0_DOMAIN}/oauth/token`,
    registration_endpoint: `${baseUrl}/register`,
    jwks_uri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access']
  };
  
  console.log('[OAUTH-METADATA] Returning:', JSON.stringify(metadata, null, 2));
  console.log('[OAUTH-METADATA] ============================================');
  res.json(metadata);
});

/**
 * OAuth2 protected resource metadata endpoint
 * Tells clients where to find the authorization server
 */
app.get('/.well-known/oauth-protected-resource', (req, res) => {
  console.log('[RESOURCE-METADATA] Request received at:', new Date().toISOString());
  console.log('[RESOURCE-METADATA] User-Agent:', req.headers['user-agent']);
  
  const baseUrl = `https://${req.get('host')}`;
  
  const metadata = {
    resource: baseUrl,
    oauth_authorization_server: `${baseUrl}/.well-known/oauth-authorization-server`
  };
  
  console.log('[RESOURCE-METADATA] Returning:', JSON.stringify(metadata, null, 2));
  res.json(metadata);
});

/**
 * Debug endpoint to check runtime environment variables
 * REMOVE IN PRODUCTION!
 */
app.get('/debug/env', (req, res) => {
  res.json({
    timestamp: new Date().toISOString(),
    processId: process.pid,
    nodeVersion: process.version,
    auth0Domain: process.env.AUTH0_DOMAIN,
    clientIdLength: process.env.CLAUDE_CLIENT_ID?.length || 0,
    clientIdFirst4: process.env.CLAUDE_CLIENT_ID?.substring(0, 4) || 'NOT_SET',
    clientIdLast4: process.env.CLAUDE_CLIENT_ID?.slice(-4) || 'NOT_SET',
    hasClientSecret: !!process.env.CLAUDE_CLIENT_SECRET,
    renderServiceName: process.env.RENDER_SERVICE_NAME,
    renderServiceId: process.env.RENDER_SERVICE_ID,
    defaultsUsed: {
      auth0Domain: AUTH0_DOMAIN === 'dev-xzj81p1mmm7ek4m5.uk.auth0.com',
      clientId: !process.env.CLAUDE_CLIENT_ID,
      clientSecret: !process.env.CLAUDE_CLIENT_SECRET
    }
  });
});

/**
 * OAuth flow test endpoint
 */
app.get('/test/oauth-flow', async (req, res) => {
  const authUrl = `https://${process.env.AUTH0_DOMAIN || AUTH0_DOMAIN}/authorize?` + 
    new URLSearchParams({
      response_type: 'code',
      client_id: process.env.CLAUDE_CLIENT_ID || 'NOT_SET',
      redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
      scope: 'openid profile email offline_access',
      state: 'test-state-' + Date.now()
    });
  
  res.json({
    message: 'This is the OAuth URL that should be used',
    authUrl,
    clientIdUsed: (process.env.CLAUDE_CLIENT_ID || 'NOT_SET').substring(0, 4) + '...',
    auth0Domain: process.env.AUTH0_DOMAIN || AUTH0_DOMAIN
  });
});

/**
 * Dynamic Client Registration endpoint
 * Creates OAuth clients dynamically for Claude Desktop
 */
app.post('/register', async (req, res) => {
  try {
    const timestamp = Date.now();
    console.log('[REGISTER] ============================================');
    console.log(`[REGISTER-${timestamp}] CLAUDE IS CALLING REGISTER!`);
    console.log(`[REGISTER-${timestamp}] Time:`, new Date().toISOString());
    console.log(`[REGISTER-${timestamp}] Headers:`, JSON.stringify(req.headers, null, 2));
    console.log(`[REGISTER-${timestamp}] Body:`, JSON.stringify(req.body, null, 2));
    console.log(`[REGISTER-${timestamp}] Client name from request:`, req.body.client_name);
    
    const {
      client_name,
      redirect_uris,
      grant_types = ['authorization_code'],
      response_types = ['code'],
      token_endpoint_auth_method = 'client_secret_post'
    } = req.body;
    
    // Log environment variable status
    const actualClientId = process.env.CLAUDE_CLIENT_ID;
    const actualClientSecret = process.env.CLAUDE_CLIENT_SECRET;
    
    console.log('[REGISTER] Environment check:', {
      envClientIdExists: !!actualClientId,
      envClientIdFirst4: actualClientId?.substring(0, 4) || 'NONE',
      envClientIdLast4: actualClientId?.slice(-4) || 'NONE',
      envClientIdLength: actualClientId?.length || 0,
      hasEnvSecret: !!actualClientSecret,
      auth0Domain: process.env.AUTH0_DOMAIN || AUTH0_DOMAIN,
      managementClientId: !!AUTH0_MANAGEMENT_CLIENT_ID,
      managementSecret: !!AUTH0_MANAGEMENT_CLIENT_SECRET
    });
    
    // Validate required fields
    if (!client_name || !redirect_uris || !Array.isArray(redirect_uris)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'client_name and redirect_uris are required'
      });
    }
    
    // If Auth0 Management API credentials are not configured, 
    // return a pre-configured client for Claude Desktop
    if (!AUTH0_MANAGEMENT_CLIENT_ID || !AUTH0_MANAGEMENT_CLIENT_SECRET) {
      console.log('[REGISTER] No Management API credentials, using pre-configured client');
      
      const responseClientId = actualClientId || 'promptforge-claude-client';
      const responseClientSecret = actualClientSecret || 'temporary-secret-replace-me';
      
      console.log('[REGISTER] Response values:', {
        usingEnvClientId: !!actualClientId,
        responseClientIdFirst4: responseClientId.substring(0, 4),
        responseClientIdLast4: responseClientId.slice(-4),
        responseClientIdLength: responseClientId.length,
        hasResponseSecret: !!responseClientSecret
      });
      
      const response = {
        client_id: responseClientId,
        client_secret: responseClientSecret,
        client_name: client_name,
        redirect_uris: redirect_uris,
        grant_types: grant_types,
        response_types: response_types,
        token_endpoint_auth_method: token_endpoint_auth_method,
        scope: 'openid profile email mcp:access'
      };
      
      console.log('[REGISTER] Sending response with client_id:', responseClientId.substring(0, 4) + '...' + responseClientId.slice(-4));
      console.log('[REGISTER] Full response:', JSON.stringify(response, null, 2));
      console.log('[REGISTER] ============================================');
      
      return res.json(response);
    }
    
    // TODO: Implement actual Auth0 Management API integration
    // This would involve:
    // 1. Getting Management API access token
    // 2. Creating application via Management API
    // 3. Returning the created client details
    
    // For now, return an error indicating DCR is not fully implemented
    return res.status(501).json({
      error: 'not_implemented',
      error_description: 'Dynamic client registration with Auth0 Management API is not yet implemented. Please use pre-configured client credentials.'
    });
    
  } catch (error) {
    console.error('[DCR] Registration error:', error);
    return res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to register client'
    });
  }
});

// Add HEAD request handler with OAuth hints
app.head('/', (req, res) => {
  console.log('[HEAD /] Request from:', req.headers['user-agent']);
  console.log('[HEAD /] Headers:', JSON.stringify(req.headers, null, 2));
  
  res.setHeader('X-MCP-OAuth-Required', 'true');
  res.setHeader('X-MCP-OAuth-Discovery', '/.well-known/oauth-authorization-server');
  res.setHeader('Link', '</.well-known/oauth-authorization-server>; rel="oauth-authorization-server"');
  res.sendStatus(200);
});

// SSE endpoint for streaming - MUST be defined before POST /
app.get('/', async (req, res) => {
  try {
    console.log('[SSE/GET /] Request received');
    console.log('[SSE/GET /] Headers:', JSON.stringify(req.headers, null, 2));
    
    // Check if this is an unauthorized request
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // Send OAuth discovery hint for unauthorized requests
      console.log('[SSE/GET /] Unauthorized - sending OAuth discovery');
      res.status(401)
         .set('WWW-Authenticate', 'Bearer realm="PromptForge"')
         .json({
        error: 'unauthorized',
        error_description: 'Authentication required',
        oauth_discovery_url: '/.well-known/oauth-authorization-server'
      });
      return;
    }
    
    console.log('[SSE Connection] Authorized client connected for streaming');
    
    // Validate the token
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      try {
        const decoded = jwt.decode(token, { complete: true });
        if (decoded && decoded.header && decoded.header.kid) {
          const key = await jwksClient.getSigningKey(decoded.header.kid);
          const signingKey = key.getPublicKey();
          const verified = jwt.verify(token, signingKey, {
            audience: AUTH0_AUDIENCE,
            issuer: `https://${AUTH0_DOMAIN}/`,
            algorithms: ['RS256']
          });
          console.log('[SSE Connection] Authenticated user:', verified.sub);
        }
      } catch (error) {
        console.log('[SSE Connection] Auth check failed (continuing anyway):', error.message);
      }
    }
    
    // Set SSE headers - MUST be done after any auth checks
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
    
  } catch (error) {
    console.error('[SSE Connection] Error:', error);
    // If headers haven't been sent, send error response
    if (!res.headersSent) {
      res.status(500).json({ error: 'SSE connection failed' });
    }
  }
});

/**
 * Main MCP endpoint at root path for Claude Chat
 * POST / - handles JSON-RPC methods
 */
app.post('/', validateAuth0Token, (req, res) => {
  try {
    const { method, params, id } = req.body;
    
    // Log incoming requests for debugging
    console.log(`[MCP Request] Method: ${method}, ID: ${id}, User: ${req.user?.sub}`);
    
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

/**
 * Main MCP endpoint that handles all JSON-RPC methods
 * Also available at /mcp for backward compatibility
 */
app.post('/mcp', validateAuth0Token, (req, res) => {
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
app.post('/api/mcp/transform', validateAuth0Token, (req, res) => {
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

/**
 * OAuth Authorization Endpoint
 * GET /authorize
 * 
 * This endpoint shows the authorization page where users can
 * authorize Claude Desktop to access PromptForge
 */
app.get('/authorize', (req, res) => {
  try {
    console.log('[AUTHORIZE] Request received:', {
      query: req.query,
      headers: req.headers
    });
    
    // Serve the authorization page
    res.sendFile(path.join(__dirname, 'authorize.html'));
  } catch (error) {
    console.error('[AUTHORIZE] Error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to load authorization page'
    });
  }
});

// Health check endpoint with detailed status
app.get('/health', (req, res) => {
  console.log('[HEALTH] Health check requested at:', new Date().toISOString());
  console.log('[HEALTH] Request from:', req.headers['user-agent']);
  
  const response = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    auth0_configured: !!process.env.AUTH0_DOMAIN,
    client_configured: !!process.env.CLAUDE_CLIENT_ID,
    client_secret_configured: !!process.env.CLAUDE_CLIENT_SECRET,
    auth0_domain: process.env.AUTH0_DOMAIN || AUTH0_DOMAIN,
    environment: {
      node_version: process.version,
      platform: process.platform,
      pid: process.pid
    },
    endpoints: {
      oauth_metadata: '/.well-known/oauth-authorization-server',
      resource_metadata: '/.well-known/oauth-protected-resource',
      register: '/register',
      authorize: '/authorize',
      mcp: '/mcp',
      sse: '/' 
    }
  };
  
  console.log('[HEALTH] Returning:', JSON.stringify(response, null, 2));
  res.json(response);
});

// Add debug endpoint to check if DCR was called
app.get('/debug/dcr-status', (req, res) => {
  res.json({
    message: 'Check server logs for DCR calls',
    timestamp: new Date().toISOString(),
    hint: 'If no [REGISTER] logs appear, Claude is not calling the DCR endpoint'
  });
});

// Test token exchange endpoint
app.post('/debug/test-token', async (req, res) => {
  console.log('[TEST-TOKEN] Testing token exchange');
  const { code, client_id, client_secret } = req.body;
  
  try {
    const tokenUrl = `https://${AUTH0_DOMAIN}/oauth/token`;
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code || 'test-code',
      client_id: client_id || process.env.CLAUDE_CLIENT_ID,
      client_secret: client_secret || process.env.CLAUDE_CLIENT_SECRET,
      redirect_uri: 'https://claude.ai/api/mcp/auth_callback'
    });
    
    console.log('[TEST-TOKEN] Request to:', tokenUrl);
    console.log('[TEST-TOKEN] Params:', params.toString());
    
    res.json({
      message: 'Token exchange test',
      tokenUrl,
      params: Object.fromEntries(params),
      note: 'Use this to test if token exchange works with your Auth0 setup'
    });
  } catch (error) {
    console.error('[TEST-TOKEN] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add global request logging middleware before catch-all
app.use((req, res, next) => {
  // Skip if response already sent
  if (res.headersSent) {
    return next();
  }
  
  console.log(`[REQUEST] ${req.method} ${req.path} at ${new Date().toISOString()}`);
  console.log('[REQUEST] Headers:', JSON.stringify(req.headers, null, 2));
  if (req.method === 'POST' && req.body) {
    console.log('[REQUEST] Body:', JSON.stringify(req.body, null, 2));
  }
  next();
});

// Add catch-all route to log any unhandled requests
app.use('*', (req, res) => {
  // Don't process if response already sent
  if (res.headersSent) {
    return;
  }
  
  console.log('[404] ============================================');
  console.log(`[404] Unhandled Request: ${req.method} ${req.originalUrl}`);
  console.log(`[404] Headers:`, JSON.stringify(req.headers, null, 2));
  console.log(`[404] Body:`, JSON.stringify(req.body, null, 2));
  console.log('[404] ============================================');
  
  res.status(404).json({
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.originalUrl}`,
    available_endpoints: [
      '/.well-known/oauth-authorization-server',
      '/.well-known/oauth-protected-resource',
      '/register',
      '/authorize',
      '/health',
      '/mcp'
    ]
  });
});

// Global error handler
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

const PORT = process.env.PORT || 3006;
app.listen(PORT, () => {
  console.log(`PromptForge MCP server running on port ${PORT}`);
  console.log(`MCP endpoint: http://localhost:${PORT}/mcp`);
  console.log(`Auth0 Domain: ${AUTH0_DOMAIN}`);
  console.log(`Auth0 Audience: ${AUTH0_AUDIENCE}`);
  console.log(`Registration endpoint: http://localhost:${PORT}/register`);
  console.log(`Instructions loaded: ${PROMPTFORGE_INSTRUCTIONS ? 'Yes' : 'No'}`);
});