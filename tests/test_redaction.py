# SPDX-License-Identifier: Apache-2.0
"""Tests for the redaction hook."""

from __future__ import annotations

from receipt_kernel.redact import redact, RedactionReport
from receipt_kernel.store_sqlite import SqliteReceiptStore


class TestRedactionPatterns:
    """Verify secret patterns are caught."""

    def test_anthropic_key(self):
        data = b'{"key": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}'
        result, report = redact(data, "application/json", "public")
        assert report.redacted
        assert b"sk-ant-" not in result
        assert b"[REDACTED:anthropic_key]" in result

    def test_openai_key(self):
        data = b'config = "sk-abcdefghijklmnopqrstuvwxyz1234567890"'
        result, report = redact(data, "text/plain", "public")
        assert report.redacted
        assert b"sk-abcdef" not in result

    def test_bearer_token(self):
        data = b'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghij'
        result, report = redact(data, "text/plain", "public")
        assert report.redacted
        assert b"eyJhbG" not in result

    def test_aws_access_key(self):
        data = b'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        result, report = redact(data, "text/plain", "public")
        assert report.redacted
        assert b"AKIAIOSF" not in result

    def test_password_field(self):
        data = b'{"password": "super_secret_123"}'
        result, report = redact(data, "application/json", "public")
        assert report.redacted
        assert b"super_secret" not in result

    def test_private_key(self):
        data = b'-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg\n-----END PRIVATE KEY-----'
        result, report = redact(data, "text/plain", "public")
        assert report.redacted
        assert b"MIIEvg" not in result

    def test_github_token(self):
        data = b'GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890'
        result, report = redact(data, "text/plain", "public")
        assert report.redacted
        assert b"ghp_abcdef" not in result

    def test_connection_string(self):
        data = b'DATABASE_URL=postgres://user:pass@host:5432/db'
        result, report = redact(data, "text/plain", "public")
        assert report.redacted
        assert b"user:pass" not in result

    def test_generic_secret_assign(self):
        data = b'api_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"'
        result, report = redact(data, "text/plain", "public")
        assert report.redacted

    def test_no_false_positive_on_normal_text(self):
        data = b'This is a normal message with no secrets.'
        result, report = redact(data, "text/plain", "public")
        assert not report.redacted
        assert result == data

    def test_binary_content_skipped(self):
        data = b'\x00\x01\x02sk-ant-api03-secret'
        result, report = redact(data, "application/octet-stream", "public")
        assert not report.redacted
        assert result == data

    def test_multiple_secrets(self):
        data = b'key1=sk-ant-api03-abcdefghijklmnopqrstuvwxyz password="hunter2verylongpassword"'
        result, report = redact(data, "text/plain", "public")
        assert report.redacted
        assert len(report.hits) >= 2

    def test_report_has_no_actual_secrets(self):
        """Redaction report must not contain the actual secret values."""
        data = b'token = "sk-ant-api03-mysupersecretkey12345"'
        _, report = redact(data, "text/plain", "public")
        report_str = str(report.to_dict())
        assert "mysupersecret" not in report_str


class TestRedactionInStore:
    """Verify redaction is applied during blob storage."""

    def test_store_redacts_by_default(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=True)
        store.initialize_schema()

        data = b'{"api_key": "sk-ant-api03-secretvalue1234567890abcdef"}'
        ref = store.put_blob(data, content_type="application/json")

        stored = store.get_blob(ref.sha256)
        assert stored is not None
        assert b"sk-ant-" not in stored
        assert b"[REDACTED:" in stored
        store.close()

    def test_store_redaction_disabled(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()

        data = b'{"api_key": "sk-ant-api03-secretvalue1234567890abcdef"}'
        ref = store.put_blob(data, content_type="application/json")

        stored = store.get_blob(ref.sha256)
        assert stored is not None
        assert b"sk-ant-" in stored  # not redacted
        store.close()

    def test_redaction_report_stored(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=True)
        store.initialize_schema()

        data = b'token = "sk-ant-api03-secretvalue1234567890abcdef"'
        ref = store.put_blob(data, content_type="text/plain")

        meta = store.get_blob_meta(ref.sha256)
        assert meta is not None
        assert meta["redaction_report"] is not None
        assert meta["redaction_report"]["redacted"] is True
        store.close()

    def test_custom_redactor(self, tmp_path):
        def custom(data, ct, ec, oh):
            return b"CUSTOM_REDACTED", RedactionReport(redacted=True)

        store = SqliteReceiptStore(
            str(tmp_path / "test.db"),
            redaction_enabled=True,
            custom_redactor=custom,
        )
        store.initialize_schema()

        ref = store.put_blob(b"anything", content_type="text/plain")
        stored = store.get_blob(ref.sha256)
        assert stored == b"CUSTOM_REDACTED"
        store.close()


class TestRedactionProof:
    """Prove that original secret bytes are NEVER stored anywhere in the DB."""

    SECRETS = [
        b'sk-ant-api03-realsecretvalue1234567890',
        b'ghp_abcdefghijklmnopqrstuvwxyz1234567890',
        b'AKIAIOSFODNN7EXAMPLE',
        b'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.realtoken',
    ]

    def test_secret_not_in_blob_data(self, tmp_path):
        """After redaction, the blob data must NOT contain the original secret."""
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=True)
        store.initialize_schema()

        for secret in self.SECRETS:
            data = b'config = "' + secret + b'"'
            ref = store.put_blob(data, content_type="text/plain")
            stored = store.get_blob(ref.sha256)
            assert stored is not None
            assert secret not in stored, (
                f"Secret {secret[:20]}... found in stored blob data after redaction"
            )
        store.close()

    def test_secret_not_in_raw_db(self, tmp_path):
        """The secret must not appear anywhere in the raw SQLite file bytes."""
        db_path = tmp_path / "test.db"
        store = SqliteReceiptStore(str(db_path), redaction_enabled=True)
        store.initialize_schema()

        secret = b'sk-ant-api03-supersecretkey987654321abcdef'
        data = b'{"api_key": "' + secret + b'"}'
        store.put_blob(data, content_type="application/json")
        store.close()

        # Read raw DB bytes and verify secret isn't there
        raw_bytes = db_path.read_bytes()
        assert secret not in raw_bytes, (
            "Secret found in raw SQLite file — redaction failed to prevent storage"
        )

    def test_secret_not_in_redaction_report(self, tmp_path):
        """The redaction report must not contain the actual secret values."""
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=True)
        store.initialize_schema()

        secret = b'sk-ant-api03-dontleakme12345678901234'
        data = b'token = "' + secret + b'"'
        ref = store.put_blob(data, content_type="text/plain")

        meta = store.get_blob_meta(ref.sha256)
        assert meta is not None
        report = meta.get("redaction_report")
        assert report is not None
        # The report should contain pattern names and offsets, not the secret
        import json
        report_str = json.dumps(report)
        assert secret.decode() not in report_str, (
            "Secret value found in redaction report metadata"
        )
        store.close()
