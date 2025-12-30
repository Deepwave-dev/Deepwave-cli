# -*- mode: python ; coding: utf-8 -*-

import sys
import os
from pathlib import Path

# Get the project root directory
# The workflow runs PyInstaller from the project root, so we can use CWD
# This is more reliable than trying to calculate from SPECPATH

# Get current working directory (should be project root when workflow runs)
project_root = Path(os.getcwd()).resolve()

# Calculate absolute path to main.py
main_py_absolute = project_root / 'cli' / 'main.py'

# Convert to string for PyInstaller
main_py_str = str(main_py_absolute.resolve())

block_cipher = None

a = Analysis(
    [main_py_str],  # Absolute path to avoid path resolution issues
    pathex=[
        str(project_root),
        str(project_root / 'engine'),
        str(project_root / 'cli'),
    ],
    binaries=[],
    datas=[
        (str(project_root / 'engine' / 'parser' / 'queries'), 'engine/parser/queries'),
    ],
    hiddenimports=[
        'click',
        'click.core',
        'click.decorators',
        'click.utils',
        'requests',
        'git',
        'git.cmd',
        'git.repo',
        'git.objects',
        'tree_sitter',
        'tree_sitter_languages',
        'tree_sitter_python',
        'pydantic',
        'pydantic._internal',
        'engine',
        'engine.models',
        'engine.graph',
        'engine.parser',
        'engine.binder',
        'engine.frameworks',
        'engine.bundle',
        'cli',
        'cli.commands',
        'cli.commands.analyze',
        'cli.commands.login',
        'cli.commands.upload',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='deepwave',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

