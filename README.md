# Deepwave CLI

Command-line interface for Deepwave - Analyze codebases locally and upload results.

## Installation

Install with one command:

```bash
curl -fsSL https://raw.githubusercontent.com/Deepwave-dev/Deepwave-cli/main/install.sh | bash
```

## Quick Start

1. **Install the CLI** (see above)

2. **Get your authentication token:**
   - Visit your Deepwave project
   - Click "Get CLI Token" button
   - Copy the token

3. **Login:**
   ```bash
   deepwave login --token <your-token>
   ```

4. **Analyze a repository:**
   ```bash
   cd /path/to/your/repo
   deepwave analyze . --project-id <your-project-id>
   ```

5. **View results:**
   - Go back to your Deepwave project
   - See your codebase graph
   - Ask questions in the Knowledge tab

## Documentation

For detailed instructions, see [QUICK_START.md](QUICK_START.md).

## Releases

Pre-built binaries for macOS, Linux, and Windows are available in [Releases](https://github.com/Deepwave-dev/Deepwave-cli/releases).

## Building from Source

```bash
git clone https://github.com/Deepwave-dev/Deepwave-cli.git
cd Deepwave-cli
pip install -r cli/requirements.txt
python3 -m cli.main --help
```

## License

[Add your license here]
