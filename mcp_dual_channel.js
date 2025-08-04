// SSE Session Manager for MCP Server
class SSESessionManager {
  constructor() {
    this.connections = new Map(); // connectionId -> response object
    this.cleanupInterval = setInterval(() => this.cleanup(), 30000); // Clean up every 30s
  }

  // Add new SSE connection
  addConnection(connectionId, res) {
    // Set SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Cache-Control'
    });

    // Send initial connection confirmation
    res.write(`data: ${JSON.stringify({
      type: 'connection',
      status: 'connected',
      connectionId
    })}\n\n`);

    this.connections.set(connectionId, {
      response: res,
      lastSeen: Date.now(),
      connected: true
    });

    // Handle connection close
    res.on('close', () => {
      this.removeConnection(connectionId);
    });

    res.on('error', (err) => {
      console.error(`SSE connection error for ${connectionId}:`, err);
      this.removeConnection(connectionId);
    });

    console.log(`SSE connection established: ${connectionId}`);
  }

  // Remove connection
  removeConnection(connectionId) {
    const connection = this.connections.get(connectionId);
    if (connection) {
      connection.connected = false;
      if (!connection.response.destroyed) {
        connection.response.end();
      }
      this.connections.delete(connectionId);
      console.log(`SSE connection removed: ${connectionId}`);
    }
  }

  // Send MCP message to specific connection
  sendMCPMessage(connectionId, mcpResponse) {
    const connection = this.connections.get(connectionId);
    if (connection && connection.connected && !connection.response.destroyed) {
      try {
        const sseMessage = `data: ${JSON.stringify(mcpResponse)}\n\n`;
        connection.response.write(sseMessage);
        connection.lastSeen = Date.now();
        return true;
      } catch (error) {
        console.error(`Error sending SSE message to ${connectionId}:`, error);
        this.removeConnection(connectionId);
        return false;
      }
    }
    return false;
  }

  // Broadcast to all connections
  broadcast(mcpResponse) {
    let sentCount = 0;
    for (const [connectionId, connection] of this.connections) {
      if (this.sendMCPMessage(connectionId, mcpResponse)) {
        sentCount++;
      }
    }
    return sentCount;
  }

  // Clean up stale connections
  cleanup() {
    const now = Date.now();
    const staleThreshold = 5 * 60 * 1000; // 5 minutes

    for (const [connectionId, connection] of this.connections) {
      if (now - connection.lastSeen > staleThreshold) {
        console.log(`Cleaning up stale SSE connection: ${connectionId}`);
        this.removeConnection(connectionId);
      }
    }
  }

  // Get connection count
  getConnectionCount() {
    return this.connections.size;
  }
}

// MCP Response Handler
class MCPResponseHandler {
  constructor() {
    this.sseManager = new SSESessionManager();
  }

  // Send dual-channel MCP response
  sendMCPResponse(req, res, mcpResponse, connectionId = null) {
    // Always send HTTP response
    res.json(mcpResponse);

    // Also send via SSE if connectionId provided
    if (connectionId) {
      this.sseManager.sendMCPMessage(connectionId, mcpResponse);
    } else {
      // Broadcast to all SSE connections if no specific connection
      this.sseManager.broadcast(mcpResponse);
    }
  }

  // Handle SSE endpoint
  handleSSEConnection(req, res) {
    const connectionId = req.query.connectionId || `conn_${Date.now()}_${Math.random()}`;
    this.sseManager.addConnection(connectionId, res);
    return connectionId;
  }
}

// Express.js integration example
const express = require('express');
const app = express();
const mcpHandler = new MCPResponseHandler();

// SSE endpoint for Claude Desktop
app.get('/mcp/sse', (req, res) => {
  const connectionId = mcpHandler.handleSSEConnection(req, res);
  // Store connectionId in session or return it to client if needed
});

// Standard MCP endpoints with dual-channel response
app.post('/mcp/tools/list', (req, res) => {
  const connectionId = req.headers['x-connection-id'] || req.query.connectionId;
  
  const toolsResponse = {
    tools: [
      {
        name: "example_tool",
        description: "An example tool",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" }
          }
        }
      }
    ]
  };

  // Send via both channels
  mcpHandler.sendMCPResponse(req, res, toolsResponse, connectionId);
});

app.post('/mcp/tools/call', (req, res) => {
  const connectionId = req.headers['x-connection-id'] || req.query.connectionId;
  const { name, arguments: args } = req.body;

  // Process tool call
  const result = processToolCall(name, args);
  
  const callResponse = {
    content: [
      {
        type: "text",
        text: result
      }
    ]
  };

  // Send via both channels
  mcpHandler.sendMCPResponse(req, res, callResponse, connectionId);
});

// Initialize endpoint that Claude Desktop calls first
app.post('/mcp/initialize', (req, res) => {
  const connectionId = req.headers['x-connection-id'] || req.query.connectionId;
  
  const initResponse = {
    protocolVersion: "2024-11-05",
    capabilities: {
      tools: {},
      logging: {}
    },
    serverInfo: {
      name: "PromptForge",
      version: "1.0.0"
    }
  };

  // Send via both channels
  mcpHandler.sendMCPResponse(req, res, initResponse, connectionId);
});

function processToolCall(name, args) {
  // Your tool implementation here
  return `Tool ${name} executed with args: ${JSON.stringify(args)}`;
}

// Keep-alive ping for SSE connections
setInterval(() => {
  const pingMessage = {
    type: 'ping',
    timestamp: Date.now()
  };
  mcpHandler.sseManager.broadcast(pingMessage);
}, 30000); // Every 30 seconds

module.exports = { MCPResponseHandler, SSESessionManager };