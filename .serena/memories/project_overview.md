# SUPERPROMPT2.0 Project Overview

This project is called **PromptForge MCP Server** - a hybrid approach to transforming natural language prompts into structured XML format.

## Purpose
PromptForge is an MCP (Model Context Protocol) server that converts ambiguous natural language prompts into well-structured XML format. It helps reduce ambiguity, anchor attention, and improve reliability across LLM interactions by enforcing a consistent prompt structure.

## Main Features
- Transforms natural language prompts using a hybrid MCP approach
- Provides OAuth authentication for Claude Desktop integration
- Returns transformation instructions that LLMs can execute
- Customizable transformation rules via XML configuration

## Integration
The server can be connected to:
- Claude Desktop (using static OAuth credentials)
- Other MCP-compatible clients
- Direct HTTP API calls

## Key URLs
- GitHub Repository: https://github.com/zabarich/PromptForge
- Deployed Server: https://promptforge-w36c.onrender.com

## OAuth Credentials
- Client ID: promptforge-static-client
- Client Secret: promptforge-static-secret-2025

## Project Structure
- Main server implementation: server.js
- Transformation instructions: promptforge-instructions.xml
- Serena MCP integration: serena/ subdirectory (Python-based coding agent toolkit)