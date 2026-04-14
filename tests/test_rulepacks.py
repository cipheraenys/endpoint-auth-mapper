"""Validate that every bundled rule pack loads and compiles."""

from __future__ import annotations

from authmapper.core.rulepack import bundled_rulepack_dir, load_rulepacks


def test_all_bundled_rulepacks_load():
    packs = load_rulepacks()
    assert len(packs) >= 8  # php, node, flask, django, spring, go, rails, aspnet
    names = {p.name for p in packs}
    assert {"php-native", "node-express", "java-spring"} <= names


def test_every_pack_has_globs_and_signals():
    for pack in load_rulepacks():
        assert pack.file_globs, f"{pack.name} has no file_globs"
        assert pack.auth_signals, f"{pack.name} has no auth_signals"


def test_bundled_dir_exists():
    assert bundled_rulepack_dir().is_dir()
