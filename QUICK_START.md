# ⚡ Deepwave Quick Start

## For End Users

### 1. Install CLI

**Option A: From source (works now)**

```bash
git clone https://github.com/yourusername/deepwave.git
cd deepwave
pip install -r cli/requirements.txt
```

**Option B: One-line install (ready now!)**

```bash
curl -fsSL https://raw.githubusercontent.com/Deepwave-dev/Deepwave-cli/main/install.sh | bash
```

### 2. Sign Up & Get Token

1. Visit https://app.deepwave.dev
2. Sign up / Sign in
3. Create project
4. Click "Get CLI Token" button

### 3. Login

```bash
# Source: python3 -m cli.main login --token <paste-token>
# Binary: deepwave login --token <paste-token>
```

### 4. Analyze

```bash
cd /path/to/your/repo
# Source: python3 -m cli.main analyze . --project-id <your-project-id>
# Binary: deepwave analyze . --project-id <your-project-id>
```

### 5. View Results

- Go back to web app
- See your codebase graph
- Ask questions in Knowledge tab

---

## That's It! 🎉

**Total time: ~5 minutes**

For detailed guide, see `USER_GUIDE.md`
