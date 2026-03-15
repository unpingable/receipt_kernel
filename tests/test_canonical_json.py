# SPDX-License-Identifier: Apache-2.0
"""Tests for canonical JSON serialization and hash determinism."""

from __future__ import annotations

import json

from receipt_kernel.envelope import canonical_json, compute_hash, compute_hash_raw


class TestCanonicalJson:
    """Canonical JSON must be deterministic across key orderings."""

    def test_sorted_keys(self):
        a = canonical_json({"z": 1, "a": 2, "m": 3})
        b = canonical_json({"a": 2, "m": 3, "z": 1})
        assert a == b

    def test_compact_separators(self):
        result = canonical_json({"key": "value"})
        assert result == b'{"key":"value"}'

    def test_ascii_safe(self):
        result = canonical_json({"emoji": "\U0001f600"})
        parsed = json.loads(result)
        assert parsed["emoji"] == "\U0001f600"
        # Should be escaped in the output
        assert b"\\u" in result

    def test_nested_determinism(self):
        obj = {"outer": {"inner_z": 1, "inner_a": 2}, "top": [3, 2, 1]}
        a = canonical_json(obj)
        b = canonical_json(obj)
        assert a == b
        # Keys should be sorted at all levels
        parsed = json.loads(a)
        keys = list(json.loads(a).keys())
        assert keys == ["outer", "top"]

    def test_no_nan(self):
        """NaN and Infinity are not valid JSON."""
        import math
        import pytest
        with pytest.raises(ValueError):
            canonical_json({"val": math.nan})
        with pytest.raises(ValueError):
            canonical_json({"val": math.inf})

    def test_float_stability(self):
        """Same float value should produce same JSON."""
        a = canonical_json({"f": 1.0 / 3.0})
        b = canonical_json({"f": 1.0 / 3.0})
        assert a == b


class TestComputeHash:
    """Hash computation must be deterministic."""

    def test_same_input_same_hash(self):
        h1 = compute_hash(b"hello world")
        h2 = compute_hash(b"hello world")
        assert h1 == h2

    def test_different_input_different_hash(self):
        h1 = compute_hash(b"hello")
        h2 = compute_hash(b"world")
        assert h1 != h2

    def test_hash_has_prefix(self):
        h = compute_hash(b"test")
        assert h.startswith("sha256:")

    def test_raw_hash_no_prefix(self):
        h = compute_hash_raw(b"test")
        assert not h.startswith("sha256:")
        assert len(h) == 64  # hex sha256

    def test_hash_of_canonical_json_is_deterministic(self):
        """The composition canonical_json -> compute_hash must be deterministic."""
        obj = {"b": 2, "a": 1, "nested": {"z": 26, "a": 1}}
        h1 = compute_hash(canonical_json(obj))
        h2 = compute_hash(canonical_json(obj))
        assert h1 == h2

    def test_key_order_does_not_affect_hash(self):
        h1 = compute_hash(canonical_json({"b": 2, "a": 1}))
        h2 = compute_hash(canonical_json({"a": 1, "b": 2}))
        assert h1 == h2
