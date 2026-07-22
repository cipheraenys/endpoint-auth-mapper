"""M5 deterministic performance/resource corpus + timing receipt for parser frontends."""

from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path

from authmapper.core.v2 import AdapterInput
from authmapper.frontends import JavaScriptFrontend, RustFrontend

JS_FILE_COUNT = 400
RUST_FILE_COUNT = 400
CEILING_SECONDS = 30.0  # generous regression tripwire; never machine-tuned


def _js_corpus(root: Path) -> tuple[Path, ...]:
    (root / "package.json").write_text('{"dependencies": {}}', encoding="utf-8")
    paths = []
    for index in range(JS_FILE_COUNT):
        path = root / f"module_{index:04d}.js"
        path.write_text(
            'import express from "express";\n'
            'import { helper } from "./local";\n'
            "const router = express.Router();\n"
            f'router.get("/route/{index}", (req, res) => res.json(helper()));\n'
            "export default router;\n",
            encoding="utf-8",
        )
        paths.append(path)
    return tuple(paths)


def _rust_corpus(root: Path) -> tuple[Path, ...]:
    (root / "Cargo.toml").write_text(
        '[package]\nname = "perf"\nversion = "0.0.0"\nedition = "2021"\n', encoding="utf-8"
    )
    src = root / "src"
    src.mkdir()
    paths = []
    for index in range(RUST_FILE_COUNT):
        path = src / f"module_{index:04d}.rs"
        path.write_text(
            "use crate::helper;\n"
            f"pub fn handler_{index}() -> u32 {{ helper({index}) }}\n"
            f"pub mod inner_{index} {{ pub fn value() -> u32 {{ {index} }} }}\n",
            encoding="utf-8",
        )
        paths.append(path)
    return tuple(paths)


def _write_receipt(tmp_path: Path, name: str, files: int, total_bytes: int, elapsed: float, work: int) -> dict:
    receipt = {
        "frontend": name,
        "files": files,
        "total_bytes": total_bytes,
        "elapsed_seconds": round(elapsed, 4),
        "work_count": work,
        "python": sys.version.split()[0],
        "platform": platform.system(),
    }
    (tmp_path / f"perf-receipt-{name}.json").write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return receipt


def test_javascript_frontend_performance_is_deterministic_and_bounded(tmp_path: Path):
    paths = _js_corpus(tmp_path)
    total_bytes = sum(path.stat().st_size for path in paths)

    start = time.perf_counter()
    result = JavaScriptFrontend().parse(AdapterInput(tmp_path, paths))
    elapsed = time.perf_counter() - start

    assert len(result.sources) == JS_FILE_COUNT
    assert result.diagnostics == ()
    assert elapsed < CEILING_SECONDS

    _write_receipt(tmp_path, "javascript", JS_FILE_COUNT, total_bytes, elapsed, len(result.sources))


def test_rust_frontend_performance_is_deterministic_and_bounded(tmp_path: Path):
    paths = _rust_corpus(tmp_path)
    total_bytes = sum(path.stat().st_size for path in paths)

    start = time.perf_counter()
    analysis = RustFrontend().analyze(AdapterInput(tmp_path, paths))
    elapsed = time.perf_counter() - start

    assert analysis.diagnostics == ()
    assert len(analysis.sources) >= RUST_FILE_COUNT
    assert elapsed < CEILING_SECONDS

    _write_receipt(tmp_path, "rust", RUST_FILE_COUNT, total_bytes, elapsed, len(analysis.sources))
