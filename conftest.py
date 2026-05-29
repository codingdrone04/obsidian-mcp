"""Pytest bootstrap — must set env before `server` is imported.

server.py reads DB_PATH / VAULT_PATH and runs _init_db() at import time, so the
test database and vault are redirected to a temp dir here, before any test
module imports the server.
"""
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="mcp-test-")
os.environ.setdefault("DB_PATH", os.path.join(_tmp, "auth.db"))
os.environ.setdefault("VAULT_PATH", os.path.join(_tmp, "vault"))
os.environ.setdefault("CONSENT_PASSWORD", "testpass")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-" + "0" * 32)
os.environ.setdefault("OAUTH_DOMAIN", "http://testserver")
os.environ.setdefault("REGISTRATION_SECRET", "")  # open DCR; /admin/backup → 503
os.makedirs(os.environ["VAULT_PATH"], exist_ok=True)
