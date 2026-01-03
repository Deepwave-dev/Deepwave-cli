# Testing Guide

## Testing Device Code Flow in Production

### Prerequisites

1. **Backend running** at your production URL (e.g., `https://api.deepwave.dev` or `http://localhost:8000`)
2. **Frontend running** at your frontend URL (e.g., `https://app.deepwave.dev` or `http://localhost:3000`)
3. **CLI installed** (either from binary or `pip install`)

### Step 1: Test Device Code Flow

```bash
# Using production backend
deepwave login --api-url https://api.deepwave.dev

# Or using local backend
deepwave login --api-url http://localhost:8000
```

fo
**What happens:**

1. CLI requests device code from backend
2. You'll see:

   ```
   🔐 Device Code Authentication
      Visit: https://app.deepwave.dev/device
      Enter code: XXXX-XXXX

   ⏳ Waiting for authentication...
   ```

3. Open the frontend URL in your browser
4. Enter the code and authorize with Google
5. CLI will automatically detect authorization and complete login

### Step 2: Verify Authentication

```bash
# Check if token is saved
cat ~/.deepwave/config.json

# Test with a command that requires auth
deepwave analyze . <project-id> --no-upload
```

### Step 3: Test Full Flow

```bash
# 1. Login (if not already)
deepwave login --api-url <your-backend-url>

# 2. Analyze a repository
deepwave analyze . <project-id>

# 3. Verify upload worked (check your dashboard)
```

### Troubleshooting

**If device code flow fails:**

- Check backend logs for errors
- Verify frontend `/device` page is accessible
- Check that backend `verification_uri` matches frontend URL
- Ensure Firebase authentication is configured correctly

**If timeout occurs:**

- Default timeout is 3 minutes (180 seconds)
- Make sure you authorize within the time limit
- Check network connectivity

**If "Unknown error" appears:**

- Check backend response format
- Verify error handling in `cli/auth.py`
- Check backend logs for actual error

### Testing Checklist

- [ ] Device code generation works
- [ ] Frontend `/device` page loads
- [ ] User can enter code and authorize
- [ ] CLI receives token after authorization
- [ ] Token is saved to config
- [ ] Authenticated commands work (analyze, upload)
- [ ] Token verification works
- [ ] Error messages are clear and helpful
