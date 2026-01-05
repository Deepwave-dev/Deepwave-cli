"""Setup configuration for deepwave-cli package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "cli" / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip() for line in requirements_file.read_text().splitlines() if line.strip() and not line.startswith("#")
    ]

setup(
    name="deepwave-cli",
    version="1.0.11",
    description="Command-line interface for analyzing codebases and uploading results to Deepwave",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Deepwave",
    author_email="support@deepwave.dev",
    url="https://github.com/Deepwave-dev/Deepwave-cli",
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*", "venv"]),
    include_package_data=True,
    package_data={
        "engine": [
            "parser/queries/**/*.scm",
        ],
    },
    install_requires=requirements,
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "deepwave=cli.main:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="code-analysis cli deepwave static-analysis",
)
