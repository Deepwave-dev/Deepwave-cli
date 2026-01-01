# Deepwave CLI

Command-line interface for analyzing Python codebases and uploading results to Deepwave.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Deepwave-dev/Deepwave-cli/main/install.sh | bash
```

Or build from source:

```bash
git clone https://github.com/Deepwave-dev/Deepwave-cli.git
cd Deepwave-cli
pip install -r cli/requirements.txt
```

## Quick Start

1. **Get your authentication token** from [app.deepwave.dev](https://app.deepwave.dev)

2. **Login:**

   ```bash
   deepwave login --token <your-token>
   ```

3. **Analyze a repository:**

   ```bash
   cd /path/to/your/repo
   deepwave analyze . <your-project-id>
   ```

4. **View results** in your Deepwave project dashboard.

## Commands

### `deepwave login`

Authenticate with the Deepwave API.

```bash
deepwave login --token <token>
deepwave login --api-url <url>  # Optional: override API URL
```

### `deepwave analyze`

Analyze a repository and create a bundle.

```bash
deepwave analyze <repo-path> <project-id> [OPTIONS]
```

**Options:**

- `--repo-url TEXT` - Repository URL (auto-detected from git)
- `--branch TEXT` - Branch name (auto-detected from git)
- `--commit-sha TEXT` - Commit SHA (auto-detected from git)
- `--output PATH` - Output directory for bundle
- `--no-upload` - Skip automatic upload

**Example:**

```bash
deepwave analyze . abc123def456 --no-upload
```

### `deepwave upload`

Upload a previously created bundle.

```bash
deepwave upload <bundle-path> --project-id <project-id>
```

## Configuration

Configuration is stored in `~/.deepwave/config.json`. The default API URL is `http://localhost:8000`.

## What Gets Analyzed

The CLI analyzes your Python codebase and extracts:

- Applications, routers, and endpoints (FastAPI/Django)
- Service classes and methods
- Dependency injection chains
- Function call graphs
- Import relationships
- Class inheritance hierarchies

Results are visualized in the Deepwave web interface.

## Framework Support

- **FastAPI**: Full support
- **Django**: Basic support

## Requirements

- Python 3.12+ (for building from source)
- Git repository (for automatic metadata detection)

## License

See [LICENSE](LICENSE) file for details.
