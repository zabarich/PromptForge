const express = require('express');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Auth0 configuration
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN || 'dev-xzj81p1mmm7ek4m5.uk.auth0.com';
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || 'https://promptforge-w36c.onrender.com';
const AUTH0_CLIENT_ID = process.env.CLAUDE_CLIENT_ID || '4nRXsZNVz0umCzwkBHLzwat9ZTzyQ7yh';
const AUTH0_CLIENT_SECRET = process.env.CLAUDE_CLIENT_SECRET;

// OAuth Bridge Storage - Maps to handle Claude's dynamic client IDs
const authorizationSessions = new Map(); // Maps state -> session data
const authorizationCodes = new Map(); // Maps code -> auth data
const claudeTokens = new Map(); // Maps Claude's client_id -> Auth0 tokens

// Cleanup old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  
  // Clean authorization sessions older than 10 minutes
  for (const [state, session] of authorizationSessions.entries()) {
    if (now - session.timestamp > 10 * 60 * 1000) {
      authorizationSessions.delete(state);
    }
  }
  
  // Clean authorization codes older than 5 minutes
  for (const [code, data] of authorizationCodes.entries()) {
    if (now - data.timestamp > 5 * 60 * 1000) {
      authorizationCodes.delete(code);
    }
  }
  
  // Clean tokens older than 24 hours
  for (const [clientId, data] of claudeTokens.entries()) {
    if (now - data.timestamp > 24 * 60 * 60 * 1000) {
      claudeTokens.delete(clientId);
    }
  }
}, 5 * 60 * 1000);

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

// Log ALL requests first
app.use((req, res, next) => {
  console.log(`[ALL-REQUESTS] ${req.method} ${req.path}${req.url.includes('?') ? '?' + req.url.split('?')[1] : ''}`);
  next();
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
    token_endpoint: `${baseUrl}/oauth/token`, // Proxy token exchange too
    // REMOVED registration_endpoint - force Claude to use our client
    jwks_uri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    // Add client information
    client_id: process.env.CLAUDE_CLIENT_ID,
    client_authentication_required: false
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
    
    // Check if Claude is requesting a specific client name/ID
    const requestedClientName = req.body.client_name || '';
    console.log(`[REGISTER-${timestamp}] Requested client name:`, requestedClientName);
    
    // If Claude is sending its own client ID (like promptforge-client-TIMESTAMP)
    // we need to handle this differently
    if (requestedClientName.startsWith('promptforge-client-')) {
      console.log(`[REGISTER-${timestamp}] Claude is using dynamic client ID:`, requestedClientName);
      console.log(`[REGISTER-${timestamp}] WARNING: Claude appears to be using its own client ID`);
      console.log(`[REGISTER-${timestamp}] This client ID must exist in Auth0 or auth will fail`);
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
 * OAuth Authorization Endpoint - OAuth Bridge
 * GET /authorize
 * 
 * This endpoint accepts Claude's dynamic client_id and redirects to Auth0
 * with our real credentials, maintaining the OAuth state
 */
app.get('/authorize', (req, res) => {
  console.log('[AUTHORIZE-HIT] Someone hit /authorize endpoint!');
  try {
    console.log('[AUTHORIZE-BRIDGE] ============================================');
    console.log('[AUTHORIZE-BRIDGE] Request received:', new Date().toISOString());
    console.log('[AUTHORIZE-BRIDGE] Query params:', req.query);
    console.log('[AUTHORIZE-BRIDGE] Headers:', req.headers);
    
    const {
      response_type = 'code',
      client_id, // Claude's dynamic client_id
      redirect_uri,
      scope = 'openid profile email offline_access',
      state,
      code_challenge,
      code_challenge_method = 'S256'
    } = req.query;
    
    // Validate required parameters
    if (!client_id || !redirect_uri || !state) {
      console.log('[AUTHORIZE-BRIDGE] Missing required parameters');
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters: client_id, redirect_uri, or state'
      });
    }
    
    console.log('[AUTHORIZE-BRIDGE] Claude client_id:', client_id);
    console.log('[AUTHORIZE-BRIDGE] Redirect URI:', redirect_uri);
    
    // Generate a unique state for Auth0
    const auth0State = crypto.randomBytes(32).toString('hex');
    
    // Store session data to bridge Claude's request with Auth0's response
    const sessionData = {
      claudeClientId: client_id,
      claudeRedirectUri: redirect_uri,
      claudeState: state,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      scope: scope,
      timestamp: Date.now()
    };
    
    authorizationSessions.set(auth0State, sessionData);
    console.log('[AUTHORIZE-BRIDGE] Stored session with auth0State:', auth0State);
    
    // Build Auth0 authorization URL with OUR credentials
    const auth0Url = new URL(`https://${AUTH0_DOMAIN}/authorize`);
    auth0Url.searchParams.set('response_type', 'code');
    auth0Url.searchParams.set('client_id', AUTH0_CLIENT_ID); // Our real Auth0 client ID
    auth0Url.searchParams.set('redirect_uri', `https://promptforge-w36c.onrender.com/callback`); // Our callback
    auth0Url.searchParams.set('scope', scope);
    auth0Url.searchParams.set('state', auth0State); // Our state for Auth0
    
    // Don't include PKCE for Auth0 - we'll validate it when Claude exchanges the code
    // This is because we don't have the code_verifier that Claude generated
    
    console.log('[AUTHORIZE-BRIDGE] Redirecting to Auth0 with our credentials');
    console.log('[AUTHORIZE-BRIDGE] Auth0 URL:', auth0Url.toString());
    console.log('[AUTHORIZE-BRIDGE] ============================================');
    
    // Redirect to Auth0
    res.redirect(auth0Url.toString());
  } catch (error) {
    console.error('[AUTHORIZE-BRIDGE] Error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to initiate authorization'
    });
  }
});

/**
 * OAuth Callback Endpoint - OAuth Bridge
 * GET /callback
 * 
 * Handles the callback from Auth0 and generates a new authorization code for Claude
 */
app.get('/callback', async (req, res) => {
  try {
    console.log('[CALLBACK-BRIDGE] ============================================');
    console.log('[CALLBACK-BRIDGE] Auth0 callback received:', new Date().toISOString());
    console.log('[CALLBACK-BRIDGE] Query params:', req.query);
    
    const { code, state, error, error_description } = req.query;
    
    // Handle Auth0 errors
    if (error) {
      console.error('[CALLBACK-BRIDGE] Auth0 error:', error, error_description);
      return res.status(400).send(`
        <html>
          <body style="font-family: sans-serif; padding: 40px; text-align: center;">
            <h2>Authentication Failed</h2>
            <p style="color: #dc3545;">${error}: ${error_description || ''}</p>
            <a href="#" onclick="window.close()">Close Window</a>
          </body>
        </html>
      `);
    }
    
    // Validate required parameters
    if (!code || !state) {
      console.error('[CALLBACK-BRIDGE] Missing code or state');
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing code or state parameter'
      });
    }
    
    // Retrieve session data
    const sessionData = authorizationSessions.get(state);
    if (!sessionData) {
      console.error('[CALLBACK-BRIDGE] Invalid or expired state:', state);
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid or expired state parameter'
      });
    }
    
    console.log('[CALLBACK-BRIDGE] Session found for state:', state);
    console.log('[CALLBACK-BRIDGE] Claude client_id:', sessionData.claudeClientId);
    
    // Exchange Auth0 code for tokens
    try {
      const tokenUrl = `https://${AUTH0_DOMAIN}/oauth/token`;
      const tokenParams = {
        grant_type: 'authorization_code',
        code: code,
        client_id: AUTH0_CLIENT_ID,
        client_secret: AUTH0_CLIENT_SECRET,
        redirect_uri: `https://promptforge-w36c.onrender.com/callback`
      };
      
      // Don't include code_verifier for Auth0 - PKCE will be validated when Claude exchanges the code
      
      console.log('[CALLBACK-BRIDGE] Exchanging Auth0 code for tokens');
      const tokenResponse = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(tokenParams)
      });
      
      const tokenData = await tokenResponse.json();
      
      if (!tokenResponse.ok) {
        console.error('[CALLBACK-BRIDGE] Token exchange failed:', tokenData);
        throw new Error(tokenData.error_description || 'Token exchange failed');
      }
      
      console.log('[CALLBACK-BRIDGE] Successfully obtained Auth0 tokens');
      
      // Generate a new authorization code for Claude
      const claudeAuthCode = crypto.randomBytes(32).toString('hex');
      
      // Store the authorization code with Auth0 tokens
      const authCodeData = {
        claudeClientId: sessionData.claudeClientId,
        claudeRedirectUri: sessionData.claudeRedirectUri,
        auth0Tokens: {
          access_token: tokenData.access_token,
          id_token: tokenData.id_token,
          refresh_token: tokenData.refresh_token,
          token_type: tokenData.token_type,
          expires_in: tokenData.expires_in
        },
        codeChallenge: sessionData.codeChallenge,
        codeChallengeMethod: sessionData.codeChallengeMethod,
        scope: sessionData.scope,
        timestamp: Date.now()
      };
      
      authorizationCodes.set(claudeAuthCode, authCodeData);
      console.log('[CALLBACK-BRIDGE] Generated Claude auth code:', claudeAuthCode);
      
      // Clean up the session
      authorizationSessions.delete(state);
      
      // Redirect back to Claude with the new authorization code
      const claudeRedirectUrl = new URL(sessionData.claudeRedirectUri);
      claudeRedirectUrl.searchParams.set('code', claudeAuthCode);
      claudeRedirectUrl.searchParams.set('state', sessionData.claudeState);
      
      console.log('[CALLBACK-BRIDGE] Redirecting to Claude:', claudeRedirectUrl.toString());
      console.log('[CALLBACK-BRIDGE] ============================================');
      
      return res.redirect(claudeRedirectUrl.toString());
      
    } catch (error) {
      console.error('[CALLBACK-BRIDGE] Error exchanging code:', error);
      
      // Clean up the session
      authorizationSessions.delete(state);
      
      return res.status(500).send(`
        <html>
          <body style="font-family: sans-serif; padding: 40px; text-align: center;">
            <h2>Authentication Error</h2>
            <p style="color: #dc3545;">Failed to complete authentication. Please try again.</p>
            <p style="font-size: 14px; color: #666;">${error.message}</p>
            <a href="#" onclick="window.close()">Close Window</a>
          </body>
        </html>
      `);
    }
  } catch (error) {
    console.error('[CALLBACK-BRIDGE] Unexpected error:', error);
    return res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error during callback processing'
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

// Debug route to catch any Auth0-like paths
app.get('/oauth/authorize', (req, res) => {
  console.log('[OAUTH-CATCH] Someone hit /oauth/authorize!');
  res.redirect(`/authorize?${new URLSearchParams(req.query).toString()}`);
});

// Add debug endpoint to check if DCR was called
app.get('/debug/dcr-status', (req, res) => {
  res.json({
    message: 'Check server logs for DCR calls',
    timestamp: new Date().toISOString(),
    hint: 'If no [REGISTER] logs appear, Claude is not calling the DCR endpoint'
  });
});

// Debug endpoint to verify PKCE fix deployment
app.get('/debug/pkce-status', (req, res) => {
  res.json({
    message: 'PKCE fix status',
    timestamp: new Date().toISOString(),
    version: 'v2-no-pkce-to-auth0',
    deployment: 'd2e4cc6',
    pkce_handling: 'PKCE parameters NOT sent to Auth0, validated on token exchange'
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

/**
 * OAuth Token Endpoint - OAuth Bridge
 * POST /oauth/token
 * 
 * Exchanges Claude's authorization code for Auth0 tokens
 */
app.post('/oauth/token', async (req, res) => {
  try {
    console.log('[TOKEN-BRIDGE] ============================================');
    console.log('[TOKEN-BRIDGE] Token request received:', new Date().toISOString());
    console.log('[TOKEN-BRIDGE] Body:', {
      grant_type: req.body.grant_type,
      client_id: req.body.client_id,
      redirect_uri: req.body.redirect_uri,
      has_code: !!req.body.code,
      has_refresh_token: !!req.body.refresh_token,
      has_code_verifier: !!req.body.code_verifier
    });
    
    const {
      grant_type,
      code,
      redirect_uri,
      client_id, // Claude's dynamic client_id
      code_verifier,
      refresh_token
    } = req.body;
    
    // Validate grant type
    if (!grant_type || (grant_type !== 'authorization_code' && grant_type !== 'refresh_token')) {
      console.error('[TOKEN-BRIDGE] Invalid grant type:', grant_type);
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code and refresh_token grants are supported'
      });
    }
    
    if (grant_type === 'authorization_code') {
      // Validate required parameters
      if (!code || !client_id) {
        console.error('[TOKEN-BRIDGE] Missing required parameters');
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameters: code or client_id'
        });
      }
      
      // Retrieve stored authorization code data
      const authCodeData = authorizationCodes.get(code);
      if (!authCodeData) {
        console.error('[TOKEN-BRIDGE] Invalid or expired authorization code:', code);
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid or expired authorization code'
        });
      }
      
      // Verify client_id matches
      if (authCodeData.claudeClientId !== client_id) {
        console.error('[TOKEN-BRIDGE] Client ID mismatch:', {
          expected: authCodeData.claudeClientId,
          received: client_id
        });
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client ID mismatch'
        });
      }
      
      // Verify redirect_uri if provided
      if (redirect_uri && authCodeData.claudeRedirectUri !== redirect_uri) {
        console.error('[TOKEN-BRIDGE] Redirect URI mismatch');
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Redirect URI mismatch'
        });
      }
      
      // Validate PKCE if it was used
      if (authCodeData.codeChallenge) {
        if (!code_verifier) {
          console.error('[TOKEN-BRIDGE] Missing code_verifier for PKCE');
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Code verifier required for PKCE'
          });
        }
        
        // Verify code_verifier
        let isValid = false;
        if (authCodeData.codeChallengeMethod === 'S256') {
          const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
          isValid = hash === authCodeData.codeChallenge;
        } else {
          isValid = code_verifier === authCodeData.codeChallenge;
        }
        
        if (!isValid) {
          console.error('[TOKEN-BRIDGE] Invalid code_verifier');
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Invalid code verifier'
          });
        }
        
        console.log('[TOKEN-BRIDGE] PKCE validation successful');
      }
      
      // Delete the used authorization code
      authorizationCodes.delete(code);
      console.log('[TOKEN-BRIDGE] Authorization code consumed');
      
      // Store tokens for this client_id
      const tokenData = {
        ...authCodeData.auth0Tokens,
        timestamp: Date.now()
      };
      claudeTokens.set(client_id, tokenData);
      
      console.log('[TOKEN-BRIDGE] Returning Auth0 tokens to Claude');
      console.log('[TOKEN-BRIDGE] ============================================');
      
      // Return the Auth0 tokens to Claude
      return res.json({
        access_token: authCodeData.auth0Tokens.access_token,
        token_type: authCodeData.auth0Tokens.token_type,
        expires_in: authCodeData.auth0Tokens.expires_in,
        refresh_token: authCodeData.auth0Tokens.refresh_token,
        id_token: authCodeData.auth0Tokens.id_token,
        scope: authCodeData.scope || 'openid profile email offline_access'
      });
      
    } else if (grant_type === 'refresh_token') {
      // Handle refresh token grant
      if (!refresh_token || !client_id) {
        console.error('[TOKEN-BRIDGE] Missing refresh_token or client_id');
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameters: refresh_token or client_id'
        });
      }
      
      // Get stored tokens for this client
      const storedTokens = claudeTokens.get(client_id);
      if (!storedTokens || storedTokens.refresh_token !== refresh_token) {
        console.error('[TOKEN-BRIDGE] Invalid refresh token');
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid refresh token'
        });
      }
      
      // Exchange refresh token with Auth0
      try {
        console.log('[TOKEN-BRIDGE] Refreshing tokens with Auth0');
        const tokenUrl = `https://${AUTH0_DOMAIN}/oauth/token`;
        const tokenResponse = await fetch(tokenUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            grant_type: 'refresh_token',
            refresh_token: storedTokens.refresh_token,
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET
          })
        });
        
        const newTokenData = await tokenResponse.json();
        
        if (!tokenResponse.ok) {
          console.error('[TOKEN-BRIDGE] Auth0 refresh failed:', newTokenData);
          throw new Error(newTokenData.error_description || 'Token refresh failed');
        }
        
        // Update stored tokens
        const updatedTokenData = {
          ...newTokenData,
          timestamp: Date.now()
        };
        claudeTokens.set(client_id, updatedTokenData);
        
        console.log('[TOKEN-BRIDGE] Tokens refreshed successfully');
        console.log('[TOKEN-BRIDGE] ============================================');
        
        // Return refreshed tokens
        return res.json({
          access_token: newTokenData.access_token,
          token_type: newTokenData.token_type,
          expires_in: newTokenData.expires_in,
          refresh_token: newTokenData.refresh_token,
          id_token: newTokenData.id_token,
          scope: newTokenData.scope || 'openid profile email offline_access'
        });
        
      } catch (error) {
        console.error('[TOKEN-BRIDGE] Refresh error:', error);
        return res.status(500).json({
          error: 'server_error',
          error_description: 'Failed to refresh tokens'
        });
      }
    }
  } catch (error) {
    console.error('[TOKEN-BRIDGE] Unexpected error:', error);
    return res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error during token exchange'
    });
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