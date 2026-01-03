# Deepwave CLI

![](https://img.shields.io/badge/Python-3.8%2B-brightgreen?style=flat-square) [![PyPI]](https://pypi.org/project/deepwave-cli/)

[PyPI]: https://img.shields.io/pypi/v/deepwave-cli.svg?style=flat-square

Deepwave CLI is a command-line tool that analyzes codebases, extracts service graphs, routers, endpoints, call graphs, and dependency relationships, then uploads the results to Deepwave for interactive visualization. Understand your codebase architecture, track dependencies, and visualize your application's structure.

**Learn more at [deepwave.dev](https://deepwave.dev)**.

# Warning ⚠️
This CLI tool is still under active development. Although the repository is public, it currently serves as a public preview to share progress and direction.
The initial release date will be announced through official channels once it’s ready.

<img src="./demo.webp" />

## Get started

1. Install Deepwave CLI:

**MacOS/Linux/Windows:**

```bash
curl -fsSL https://raw.githubusercontent.com/Deepwave-dev/Deepwave-cli/main/install.sh | bash
```

**PyPI:**

```bash
pip install deepwave-cli
```

**From source:**

```bash
git clone https://github.com/Deepwave-dev/Deepwave-cli.git
cd Deepwave-cli
pip install -r cli/requirements.txt
```

NOTE: Requires [Python 3.8+](https://www.python.org/downloads/) and a Git repository for automatic metadata detection.

2. Authenticate and analyze:

```bash
# Login (interactive device code flow) using Deepwave.dev auth
deepwave login

# Analyze your repository
cd /path/to/your/repo
deepwave analyze . <your-project-id>
```

3. View results in your [Deepwave dashboard](https://deepwave.dev).

## Commands

### `deepwave login`

Authenticate with the Deepwave API using OAuth device code flow or a token.

```bash
# Interactive device code flow (opens browser)
deepwave login

# With a token
deepwave login --token <token>
```

**Device code flow:**

1. Run `deepwave login`
2. Visit [Deepwave Auth](https://deepwave.dev/device) and enter the code
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

## Reporting Bugs

We welcome your feedback. File a [GitHub issue](https://github.com/Deepwave-dev/Deepwave-cli/issues) to report bugs or suggest features.

## License

MIT License - see [LICENSE](LICENSE) file for details.
