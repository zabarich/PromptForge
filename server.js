const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
app.use(express.json());

const PROMPTFORGE_INSTRUCTIONS = fs.readFileSync('./promptforge-instructions.xml', 'utf-8');

app.post('/api/mcp/transform', (req, res) => {
  // Handle both direct prompt and MCP protocol format
  const prompt = req.body.prompt || (req.body.params && req.body.params.prompt);
  
  if (!prompt) {
    return res.status(400).json({ error: 'No prompt provided' });
  }

  // If it's an MCP request, respond in MCP format
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
    // Standard response
    res.json({
      action: 'execute_transformation',
      system_prompt: PROMPTFORGE_INSTRUCTIONS,
      user_prompt: prompt,
      directive: 'Transform the user_prompt using the system_prompt instructions and return the result in structured XML format.'
    });
  }
});

const PORT = process.env.PORT || 3006;
app.listen(PORT, () => {
  console.log(`PromptForge MCP server running on port ${PORT}`);
});