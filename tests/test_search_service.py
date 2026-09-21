from upab.search_service import find_files, resolve_search_roots


def test_resolve_search_roots_ignores_missing(tmp_path):
    existing = tmp_path / "existing"
    existing.mkdir()
    roots = resolve_search_roots([str(existing), str(tmp_path / "missing")])
    assert roots == (existing.resolve(),)


def test_find_files_requires_available_roots(tmp_path):
    try:
        find_files([str(tmp_path / "missing")], "project")
    except ValueError as exc:
        assert "no configured search roots" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_find_files_searches_configured_roots(tmp_path):
    root = tmp_path / "projects"
    root.mkdir()
    target = root / "PROJECT_STATE.yaml"
    target.write_text("state", encoding="utf-8")
    results = find_files([str(root)], "project_state")
    assert len(results) == 1
    assert results[0].path.endswith("PROJECT_STATE.yaml")
