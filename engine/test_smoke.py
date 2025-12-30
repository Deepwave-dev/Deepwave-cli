"""
Minimal smoke test for the engine structure.
Tests that basic imports and functions work.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_imports():
    """Test that all basic imports work"""
    try:
        from engine import analyze_repo
        from engine.models import FileDetail, ProjectMetadata, ServiceGraph
        from engine.graph.extractor import scan_repository
        from engine.parser import TreeSitterParser, QueryEngine
        from engine.parser.parse_cache import ParseCache
        from engine.ignore import is_excluded, detect_language

        print("✅ All imports successful")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_scan_repository():
    """Test repository scanning on the current directory"""
    try:
        from engine.graph.extractor import scan_repository

        # Test on the backend directory (should exist)
        test_path = Path(__file__).parent.parent / "backend"
        if not test_path.exists():
            print(f"⚠️  Test path doesn't exist: {test_path}")
            return False

        files = scan_repository(test_path)
        print(f"✅ scan_repository works: found {len(files)} files")
        if len(files) > 0:
            print(f"   Example: {files[0].path} ({files[0].language}, {files[0].line_count} lines)")
        return True
    except Exception as e:
        print(f"❌ scan_repository failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_parser():
    """Test parser initialization"""
    try:
        from engine.parser import TreeSitterParser
        from engine.parser.parse_cache import ParseCache

        parser = TreeSitterParser("python")
        print(f"✅ Parser initialized: {parser.get_language()}")

        cache = ParseCache(Path(__file__).parent.parent)
        print(f"✅ ParseCache initialized")
        return True
    except Exception as e:
        print(f"❌ Parser test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("🧪 Running smoke tests for engine...\n")

    results = []
    results.append(("Imports", test_imports()))
    print()
    results.append(("Repository Scanning", test_scan_repository()))
    print()
    results.append(("Parser", test_parser()))
    print()

    print("=" * 50)
    passed = sum(1 for _, result in results if result)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("✅ All tests passed! Structure is working.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Fix issues before continuing.")
        sys.exit(1)
