import hashlib
import json
import zipfile
from pathlib import Path

from engine.bundle.schema import Bundle, Manifest
from engine.graph.file_tree import build_file_tree
from engine.models import AnalysisResult, CodebaseStats, ServiceGraph


def write_bundle(result: AnalysisResult, output_dir: Path, tool_version: str = "1.0.0") -> Path:
    """Write analysis results to bundle files and create zip archive."""
    output_dir.mkdir(parents=True, exist_ok=True)

    graph: ServiceGraph = result.graph
    stats: CodebaseStats = result.stats
    project_metadata = graph.metadata

    # Build file tree from files metadata (reuse existing scan results)
    file_tree = build_file_tree(result.files)

    manifest = Manifest(
        bundle_version="1.0.0",
        tool_version=tool_version,
        repo_root=project_metadata.repository_url,
        commit_sha=project_metadata.commit_sha,
        created_at=project_metadata.parsed_at,
    )

    bundle = Bundle(manifest=manifest, graph=graph, chunks=[], stats=stats, file_tree=file_tree)

    manifest_path = output_dir / "manifest.json"
    graph_path = output_dir / "graph.json"
    chunks_path = output_dir / "chunks.jsonl"
    stats_path = output_dir / "stats.json"
    file_tree_path = output_dir / "file_tree.json"

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest.model_dump(mode="json"), f, indent=2)

    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(graph.model_dump(mode="json"), f, indent=2)

    with open(chunks_path, "w", encoding="utf-8") as f:
        pass

    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats.model_dump(mode="json"), f, indent=2)

    with open(file_tree_path, "w", encoding="utf-8") as f:
        json.dump(file_tree, f, separators=(",", ":"))

    bundle_hash = hashlib.sha256(f"{project_metadata.project_hash}{project_metadata.commit_sha}".encode()).hexdigest()[
        :12
    ]

    zip_path = output_dir / f"deepwave_bundle_{bundle_hash}.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(manifest_path, "manifest.json")
        zipf.write(graph_path, "graph.json")
        zipf.write(chunks_path, "chunks.jsonl")
        zipf.write(stats_path, "stats.json")
        zipf.write(file_tree_path, "file_tree.json")

    return zip_path
