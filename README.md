# Deepwave CLI

Command-line interface for analyzing Python codebases and uploading results to Deepwave.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Deepwave-dev/Deepwave-cli/main/install.sh | bash
```

Or install via pip:

```bash
pip install deepwave-cli
```

Or build from source:

```bash
git clone https://github.com/Deepwave-dev/Deepwave-cli.git
cd Deepwave-cli
pip install -r cli/requirements.txt
```

## Quick Start

1. **Authenticate:**

   ```bash
   # Device code flow (recommended)
   deepwave login

   # Or with a token
   deepwave login --token <your-token>
   ```

2. **Analyze and upload:**

   ```bash
   cd /path/to/your/repo
   deepwave analyze . <your-project-id>
   ```

3. **View results** in your [Deepwave dashboard](https://app.deepwave.dev).

## Commands

### `deepwave login`

Authenticate with the Deepwave API using OAuth device code flow or a token.

```bash
# Interactive device code flow (opens browser)
deepwave login

# With a token
deepwave login --token <token>

# Override API URL
deepwave login --api-url <url>
```

**Device code flow:**

1. Run `deepwave login`
2. Visit the displayed URL and enter the code
3. Authorize with your Google account
4. Authentication completes automatically

### `deepwave analyze`

Analyze a repository and automatically upload results to Deepwave.

```bash
deepwave analyze <repo-path> <project-id> [OPTIONS]
```

**Default behavior:**

- Analyzes the repository
- Creates a bundle
- Uploads to Deepwave
- Deletes bundle files after successful upload

**Options:**

- `--repo-url TEXT` - Repository URL (auto-detected from git)
- `--branch TEXT` - Branch name (auto-detected from git)
- `--commit-sha TEXT` - Commit SHA (auto-detected from git)
- `--output PATH` - Output directory for bundle files
- `--no-upload` - Skip upload (keeps bundle files)
- `--keep-files` - Keep bundle files after upload

**Examples:**

```bash
# Analyze, upload, and clean up (default)
deepwave analyze . abc123def456

# Analyze without uploading
deepwave analyze . abc123def456 --no-upload

# Analyze and upload, but keep bundle files
deepwave analyze . abc123def456 --keep-files
```

### `deepwave upload`

Upload a previously created bundle.

```bash
deepwave upload <bundle-path> --project-id <project-id>
```

## What Gets Analyzed

The CLI analyzes your Python codebase and extracts:

- **FastAPI/Django**: Applications, routers, endpoints, and dependency injection
- **Services**: Classes, methods, and service dependencies
- **Call graphs**: Function call relationships
- **Import graphs**: Module import relationships
- **Inheritance**: Class hierarchies and inheritance chains

Results are visualized in the Deepwave web interface with interactive graphs and dependency maps.

## Framework Support

- **FastAPI**: Full support (routers, dependencies, endpoints)
- **Django**: Basic support

## Requirements

- Python 3.8+ (for building from source)
- Git repository (for automatic metadata detection)

## License

MIT License - see [LICENSE](LICENSE) file for details.
