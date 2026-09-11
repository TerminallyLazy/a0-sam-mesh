"""Five-minute encrypted decisions, durable replay/quota and offline stop controls.

The encryption key is process-local: restart invalidates outstanding decisions, never
resurrects approvals. SQLite contains ciphertext, not arguments or lease bearers.
"""

import hashlib
import json
import secrets
from contextlib import contextmanager

from cryptography.fernet import Fernet

from .storage import SQLiteStorage, copy_plain_json, timestamp_us

_CIPHER = Fernet(Fernet.generate_key())


class DecisionError(RuntimeError):
    pass


class DecisionStore:
    def __init__(self, **options):
        self.storage = SQLiteStorage(**options)

    @contextmanager
    def transaction(self, scope):
        connection = self.storage.connect(scope)
        try:
            connection.execute("""CREATE TABLE IF NOT EXISTS gate_decisions (
                id TEXT PRIMARY KEY, scope TEXT NOT NULL, expires INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0, payload BLOB NOT NULL)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS gate_sessions (
                scope TEXT PRIMARY KEY, calls INTEGER NOT NULL DEFAULT 0,
                disabled INTEGER NOT NULL DEFAULT 0, active TEXT)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS gate_control (
                scope TEXT PRIMARY KEY, generation INTEGER NOT NULL, stopped INTEGER NOT NULL)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS gate_admissions (
                id TEXT PRIMARY KEY, scope TEXT NOT NULL, generation INTEGER NOT NULL)""")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO gate_control VALUES (?,0,0)", (self.control_key(scope),)
            )
            connection.execute(
                "INSERT OR IGNORE INTO gate_sessions(scope) VALUES (?)", (self.scope_key(scope),)
            )
            yield connection
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def control_key(scope):
        return json.dumps([scope.project_name, scope.agent_profile])

    @staticmethod
    def scope_key(scope):
        return json.dumps([scope.project_name, scope.agent_profile, scope.chat_id])

    @staticmethod
    def digest(decision_id):
        if type(decision_id) is not str or not 20 <= len(decision_id) <= 128:
            raise DecisionError("decision_not_found")
        return hashlib.sha256(decision_id.encode()).hexdigest()

    def _seal(self, scope, decision_id, payload):
        plain = copy_plain_json(payload)
        raw = json.dumps([self.scope_key(scope), decision_id, plain], allow_nan=False).encode()
        if len(raw) > 131072:
            raise DecisionError("decision_too_large")
        return _CIPHER.encrypt(raw)

    def _load(self, connection, scope, decision_id):
        row = connection.execute(
            "SELECT * FROM gate_decisions WHERE id=? AND scope=?",
            (self.digest(decision_id), self.scope_key(scope)),
        ).fetchone()
        if row is None:
            raise DecisionError("decision_not_found")
        if row["expires"] <= timestamp_us(self.storage.now()):
            raise DecisionError("approval_expired")
        if row["used"] != 0:
            raise DecisionError("decision_replayed")
        try:
            binding, identifier, payload = json.loads(_CIPHER.decrypt(row["payload"]))
            if binding != self.scope_key(scope) or identifier != decision_id:
                raise ValueError()
            if payload["_expires_us"] <= timestamp_us(self.storage.now()):
                raise DecisionError("approval_expired")
            return copy_plain_json(payload)
        except DecisionError:
            raise
        except Exception:
            raise DecisionError("decision_unavailable") from None

    def create(self, scope, payload):
        identifier = secrets.token_urlsafe(32)
        now = timestamp_us(self.storage.now())
        payload = dict(payload, _expires_us=now + 300000000)
        with self.transaction(scope) as db:
            db.execute(
                "DELETE FROM gate_decisions WHERE scope=? AND expires<=?",
                (self.scope_key(scope), now),
            )
            count = db.execute(
                "SELECT count(*) FROM gate_decisions WHERE scope=?", (self.scope_key(scope),)
            ).fetchone()[0]
            if count >= 128:
                raise DecisionError("decision_quota_exceeded")
            db.execute(
                "INSERT INTO gate_decisions(id,scope,expires,payload) VALUES(?,?,?,?)",
                (
                    self.digest(identifier),
                    self.scope_key(scope),
                    now + 300000000,
                    self._seal(scope, identifier, payload),
                ),
            )
        return identifier

    def load(self, scope, decision_id):
        with self.transaction(scope) as db:
            return self._load(db, scope, decision_id)

    def update(self, scope, decision_id, payload):
        with self.transaction(scope) as db:
            self._load(db, scope, decision_id)
            db.execute(
                "UPDATE gate_decisions SET payload=? WHERE id=?",
                (self._seal(scope, decision_id, payload), self.digest(decision_id)),
            )

    def disabled(self, scope):
        with self.transaction(scope) as db:
            return (
                db.execute(
                    "SELECT stopped FROM gate_control WHERE scope=?", (self.control_key(scope),)
                ).fetchone()[0]
                != 0
            )

    def claim(self, scope, decision_id, limit, expected_payload):
        """One in-flight invocation per exact session, across processes; no network here."""
        with self.transaction(scope) as db:
            current = self._load(db, scope, decision_id)
            if current != expected_payload:
                raise DecisionError("decision_changed")
            row = db.execute(
                "SELECT * FROM gate_sessions WHERE scope=?", (self.scope_key(scope),)
            ).fetchone()
            if row["disabled"] != 0:
                raise DecisionError("emergency_disconnected")
            if row["active"] is not None:
                raise DecisionError("invocation_in_progress")
            if type(row["calls"]) is not int or not 0 <= row["calls"] < limit:
                raise DecisionError("session_quota_exceeded")
            db.execute("UPDATE gate_decisions SET used=1 WHERE id=?", (self.digest(decision_id),))
            db.execute(
                "UPDATE gate_sessions SET calls=calls+1, active=? WHERE scope=?",
                (self.digest(decision_id), self.scope_key(scope)),
            )

    def begin_native(self, scope, limit):
        """Atomically admit a native call against the same quota and stop barrier."""
        identifier = secrets.token_urlsafe(32)
        with self.transaction(scope) as db:
            control = db.execute(
                "SELECT * FROM gate_control WHERE scope=?", (self.control_key(scope),)
            ).fetchone()
            if control["stopped"]:
                raise DecisionError("emergency_disconnected")
            session = db.execute(
                "SELECT * FROM gate_sessions WHERE scope=?", (self.scope_key(scope),)
            ).fetchone()
            if session["active"] is not None:
                raise DecisionError("invocation_in_progress")
            if type(session["calls"]) is not int or not 0 <= session["calls"] < limit:
                raise DecisionError("session_quota_exceeded")
            db.execute(
                "UPDATE gate_sessions SET calls=calls+1, active=? WHERE scope=?",
                (self.digest(identifier), self.scope_key(scope)),
            )
            db.execute(
                "INSERT INTO gate_admissions VALUES (?,?,?)",
                (self.digest(identifier), self.control_key(scope), control["generation"]),
            )
        return identifier

    def finish(self, scope, decision_id):
        with self.transaction(scope) as db:
            db.execute(
                "UPDATE gate_sessions SET active=NULL WHERE scope=? AND active=?",
                (self.scope_key(scope), self.digest(decision_id)),
            )
            db.execute("DELETE FROM gate_admissions WHERE id=?", (self.digest(decision_id),))

    def revoke_scope(self, scope):
        with self.transaction(scope) as db:
            db.execute(
                "UPDATE gate_control SET stopped=1, generation=generation+1 WHERE scope=?",
                (self.control_key(scope),),
            )
            self._invalidate_profile(db, scope, disabled=True)
            count = db.execute(
                "SELECT count(*) FROM gate_admissions WHERE scope=?", (self.control_key(scope),)
            ).fetchone()[0]
            return {"already_admitted": count, "mutations_undone": False}

    def _invalidate_profile(self, db, scope, *, disabled):
        prefix = [scope.project_name, scope.agent_profile]
        for row in db.execute("SELECT scope FROM gate_sessions").fetchall():
            if json.loads(row["scope"])[:2] == prefix:
                db.execute(
                    "UPDATE gate_sessions SET disabled=? WHERE scope=?",
                    (int(disabled), row["scope"]),
                )
        for row in db.execute("SELECT DISTINCT scope FROM gate_decisions").fetchall():
            if json.loads(row["scope"])[:2] == prefix:
                db.execute("UPDATE gate_decisions SET used=1 WHERE scope=?", (row["scope"],))

    def resume_scope(self, scope):
        """Open a new control generation without restoring decisions, leases or quota."""
        with self.transaction(scope) as db:
            self._invalidate_profile(db, scope, disabled=False)
            db.execute(
                "UPDATE gate_control SET stopped=0, generation=generation+1 WHERE scope=?",
                (self.control_key(scope),),
            )
        return {"stopped": False, "approvals_restored": False}

    def invalidate(self, scope, decision_id):
        """A changed boundary requires a new decision even if upstream later reverts."""
        with self.transaction(scope) as db:
            db.execute(
                "UPDATE gate_decisions SET used=1 WHERE scope=? AND id=?",
                (self.scope_key(scope), self.digest(decision_id)),
            )

    def admit(self, scope, decision_id, payload):
        """Commit is the dispatch-admission boundary shared with project/profile stop.

        Work admitted before stop may complete; stop never claims to undo mutations.
        No network is performed inside this transaction.
        """
        with self.transaction(scope) as db:
            if payload["_expires_us"] <= timestamp_us(self.storage.now()):
                raise DecisionError("approval_expired")
            row = db.execute(
                "SELECT * FROM gate_control WHERE scope=?", (self.control_key(scope),)
            ).fetchone()
            if row["stopped"] != 0:
                raise DecisionError("emergency_disconnected")
            active = db.execute(
                "SELECT active FROM gate_sessions WHERE scope=?", (self.scope_key(scope),)
            ).fetchone()[0]
            if active != self.digest(decision_id):
                raise DecisionError("admission_unavailable")
            db.execute(
                "INSERT INTO gate_admissions VALUES (?,?,?)",
                (self.digest(decision_id), self.control_key(scope), row["generation"]),
            )
            return row["generation"]
