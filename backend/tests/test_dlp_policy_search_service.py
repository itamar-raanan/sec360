from app.services.dlp_policy_search import (
    EDITOR_FALLBACK_TABLE_SQL,
    EDITOR_FOREIGN_KEY_SQL,
    _enrich_editor_names,
)


class EditorLookupCursor:
    def __init__(self, editor_rows=None, account_columns=None):
        self.editor_rows = editor_rows or []
        self.account_columns = account_columns or ["VONTUUSERID", "USERNAME"]
        self.rows = []
        self.lookup_parameters = None

    def execute(self, statement, parameters=None, **keyword_parameters):
        if statement == EDITOR_FOREIGN_KEY_SQL:
            self.rows = [("PROTECT", "VONTUUSER", "VONTUUSERID")]
        elif statement == EDITOR_FALLBACK_TABLE_SQL:
            self.rows = []
        elif "SELECT column_name" in statement:
            self.rows = [(column,) for column in self.account_columns]
        elif "FROM \"PROTECT\".\"VONTUUSER\"" in statement:
            self.lookup_parameters = parameters
            self.rows = self.editor_rows
        else:
            raise AssertionError(f"Unexpected SQL: {statement}")

    def fetchall(self):
        return list(self.rows)


def test_enrich_editor_names_uses_oracle_foreign_key_metadata():
    cursor = EditorLookupCursor(editor_rows=[(3, "Administrator")])
    rows = [
        {"modified_by_id": 3, "object_name": "Executive exclusions"},
        {"modified_by_id": None, "object_name": "Imported exclusions"},
    ]

    _enrich_editor_names(cursor, rows)

    assert rows[0]["modified_by_name"] == "Administrator"
    assert rows[1]["modified_by_name"] is None
    assert cursor.lookup_parameters == {"editor_id_0": 3}


def test_enrich_editor_names_keeps_id_when_account_is_missing():
    cursor = EditorLookupCursor(editor_rows=[])
    rows = [{"modified_by_id": 99}]

    _enrich_editor_names(cursor, rows)

    assert rows == [{"modified_by_id": 99, "modified_by_name": None}]
