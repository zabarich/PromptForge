# Auth0 Setup Requirements

## Required Callback URLs

Add these URLs to your Auth0 Application's "Allowed Callback URLs" setting:

1. `https://promptforge-w36c.onrender.com/callback` - OAuth Bridge callback
2. `https://claude.ai/api/mcp/auth_callback` - Claude Desktop callback

## Environment Variables

Ensure these are set in your Render deployment:

- `AUTH0_DOMAIN` - Your Auth0 domain (e.g., dev-xzj81p1mmm7ek4m5.uk.auth0.com)
- `AUTH0_AUDIENCE` - Your API audience URL
- `CLAUDE_CLIENT_ID` - Your Auth0 application client ID
- `CLAUDE_CLIENT_SECRET` - Your Auth0 application client secret

## How to Add Callback URLs in Auth0

1. Go to [Auth0 Dashboard](https://manage.auth0.com/)
2. Navigate to Applications > Your Application
3. Go to the Settings tab
4. Find "Allowed Callback URLs"
5. Add both URLs listed above (one per line)
6. Save changes

## OAuth Bridge Flow

The OAuth bridge handles Claude's dynamic client IDs by:
1. Accepting whatever client_id Claude generates
2. Using your real Auth0 credentials behind the scenes
3. Managing the token exchange process