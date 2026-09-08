from __future__ import annotations

import asyncio
import logging
import re
from datetime import date, datetime
from decimal import Decimal
from typing import Any

logger = logging.getLogger(__name__)

MAX_DLP_POLICY_ROWS = 10_000

EDITOR_FOREIGN_KEY_SQL = """
SELECT
    referenced_constraint.owner,
    referenced_constraint.table_name,
    referenced_column.column_name
FROM all_constraints source_constraint
JOIN all_cons_columns source_column
  ON source_column.owner = source_constraint.owner
 AND source_column.constraint_name = source_constraint.constraint_name
JOIN all_constraints referenced_constraint
  ON referenced_constraint.owner = source_constraint.r_owner
 AND referenced_constraint.constraint_name = source_constraint.r_constraint_name
JOIN all_cons_columns referenced_column
  ON referenced_column.owner = referenced_constraint.owner
 AND referenced_column.constraint_name = referenced_constraint.constraint_name
 AND referenced_column.position = source_column.position
WHERE source_constraint.constraint_type = 'R'
  AND source_constraint.table_name = 'SENDERRECIPIENTPATTERN'
  AND source_column.column_name = 'MODIFIEDBYID'
ORDER BY CASE
    WHEN source_constraint.owner = SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') THEN 0
    ELSE 1
END
"""

EDITOR_FALLBACK_TABLE_SQL = """
SELECT owner, table_name, column_name
FROM all_tab_columns
WHERE table_name IN ('VONTUUSER', 'SYSTEMUSER', 'USERACCOUNT')
  AND column_name IN ('VONTUUSERID', 'USERID', 'ID')
ORDER BY
    CASE WHEN owner = SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') THEN 0 ELSE 1 END,
    CASE table_name WHEN 'VONTUUSER' THEN 0 WHEN 'SYSTEMUSER' THEN 1 ELSE 2 END,
    CASE column_name WHEN 'VONTUUSERID' THEN 0 WHEN 'USERID' THEN 1 ELSE 2 END
"""

EDITOR_NAME_COLUMNS = (
    "USERNAME",
    "LOGINNAME",
    "DISPLAYNAME",
    "NAME",
    "EMAILADDRESS",
    "EMAIL",
)

_ORACLE_IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9_$#]*$")

# This is the database portion of the analyst-provided SQL*Plus script. SQL*Plus
# directives (SPOOL, SET, EXIT) intentionally do not belong in a driver query.
DLP_POLICY_EXCLUSIONS_SQL = """
WITH condition_edges (parent_condition_id, child_condition_id) AS (
    SELECT oc.CONDITIONGROUPID, oc.ORCONDITIONID
    FROM ORCONDITION oc

    UNION

    SELECT noc.CONDITIONGROUPID, noc.NOTORCONDITIONID
    FROM NOTORCONDITION noc

    UNION

    SELECT ccc.COMPOUNDCONDITIONID, ccc.CONDITIONID
    FROM COMPOUNDCONDITIONCONDITION ccc

    UNION

    SELECT cr.COMPOUNDCONDITIONID, crcm.CONDITIONID
    FROM CONDITIONRELATION cr
    JOIN CONDITIONRELATIONCONDITIONMAP crcm
      ON crcm.CONDITIONRELATIONID = cr.CONDITIONRELATIONID
),
condition_tree (policy_id, condition_id) AS (
    SELECT p.POLICYID, p.ROOTCONDITIONID
    FROM POLICY p
    WHERE p.ROOTCONDITIONID IS NOT NULL

    UNION ALL

    SELECT ct.policy_id, ce.child_condition_id
    FROM condition_tree ct
    JOIN condition_edges ce
      ON ce.parent_condition_id = ct.condition_id
),
condition_usage AS (
    SELECT
        sc.SENDERPATTERNID AS pattern_id,
        sc.CONDITIONID AS condition_id,
        'SENDER' AS usage_type
    FROM SENDERCONDITION sc
    WHERE sc.SENDERPATTERNID IS NOT NULL

    UNION ALL

    SELECT
        rc.RECIPIENTPATTERNID AS pattern_id,
        rc.CONDITIONID AS condition_id,
        'RECIPIENT' AS usage_type
    FROM RECIPIENTCONDITION rc
    WHERE rc.RECIPIENTPATTERNID IS NOT NULL
),
policy_usage AS (
    SELECT DISTINCT cu.pattern_id, cu.usage_type, ct.policy_id
    FROM condition_usage cu
    JOIN condition_tree ct
      ON ct.condition_id = cu.condition_id
)
SELECT
    srp.SENDERRECIPIENTPATTERNID AS OBJECT_ID,
    srp.NAME AS OBJECT_NAME,
    srp.DESCRIPTION AS OBJECT_DESCRIPTION,
    CASE srp.ISDELETED
        WHEN 0 THEN 'ACTIVE'
        WHEN 1 THEN 'DELETED'
        ELSE 'UNKNOWN (' || TO_CHAR(srp.ISDELETED) || ')'
    END AS OBJECT_STATUS,
    srp.RULETYPE AS RULE_TYPE,
    NVL(pu.usage_type, 'UNUSED') AS USED_AS,
    p.POLICYID AS POLICY_ID,
    p.NAME AS POLICY_NAME,
    p.ACTIVESTATUS AS POLICY_ACTIVE_STATUS,
    CASE p.ISDELETED
        WHEN 0 THEN 'ACTIVE'
        WHEN 1 THEN 'DELETED'
        ELSE 'UNKNOWN (' || TO_CHAR(p.ISDELETED) || ')'
    END AS POLICY_RECORD_STATUS,
    srp.USERPATTERNS AS USER_PATTERNS,
    srp.IPADDRESSES AS IP_ADDRESSES,
    srp.URLDOMAINS AS URL_DOMAINS,
    srp.PERSONALEMAILBREADTH AS PERSONAL_EMAIL_BREADTH,
    srp.PERSONALEMAILEXCLUDEDDOMAINS AS PERSONAL_EMAIL_EXCLUDED_DOMAINS,
    srp.PERSONALEMAILMAXRECIPIENTS AS PERSONAL_EMAIL_MAX_RECIPIENTS,
    srp.MODIFIEDDATE AS MODIFIED_DATE,
    srp.MODIFIEDBYID AS MODIFIED_BY_ID,
    srp.UUID AS OBJECT_UUID
FROM SENDERRECIPIENTPATTERN srp
LEFT JOIN policy_usage pu
  ON pu.pattern_id = srp.SENDERRECIPIENTPATTERNID
LEFT JOIN POLICY p
  ON p.POLICYID = pu.policy_id
ORDER BY srp.NAME, p.NAME NULLS LAST, pu.usage_type NULLS LAST
"""


def _serialize_oracle_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "read"):
        value = value.read()
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def _safe_identifier(value: str) -> str:
    """Quote an identifier returned by Oracle's own data dictionary."""
    normalized = str(value).upper()
    if not _ORACLE_IDENTIFIER.fullmatch(normalized):
        raise ValueError("Oracle returned an unsafe editor-account identifier")
    return f'"{normalized}"'


def _find_editor_account_source(cursor) -> tuple[str, str, str, str] | None:
    """Discover the account table referenced by MODIFIEDBYID across DLP versions."""
    cursor.execute(EDITOR_FOREIGN_KEY_SQL)
    candidates = list(cursor.fetchall())

    # Some DLP releases do not expose the application foreign key to the
    # read-only integration account. Fall back to the known account tables,
    # while still deriving their exact columns from Oracle metadata.
    cursor.execute(EDITOR_FALLBACK_TABLE_SQL)
    candidates.extend(cursor.fetchall())

    seen: set[tuple[str, str, str]] = set()
    for owner, table_name, id_column in candidates:
        candidate = (str(owner).upper(), str(table_name).upper(), str(id_column).upper())
        if candidate in seen:
            continue
        seen.add(candidate)

        cursor.execute(
            """
            SELECT column_name
            FROM all_tab_columns
            WHERE owner = :owner AND table_name = :table_name
            """,
            owner=candidate[0],
            table_name=candidate[1],
        )
        available_columns = {str(row[0]).upper() for row in cursor.fetchall()}
        name_column = next(
            (column for column in EDITOR_NAME_COLUMNS if column in available_columns),
            None,
        )
        if candidate[2] in available_columns and name_column:
            return candidate[0], candidate[1], candidate[2], name_column
    return None


def _enrich_editor_names(cursor, rows: list[dict]) -> None:
    """Add a best-effort real editor name without making the base query fragile."""
    for row in rows:
        row["modified_by_name"] = None

    editor_ids = {
        str(row["modified_by_id"]): row["modified_by_id"]
        for row in rows
        if row.get("modified_by_id") is not None
    }
    if not editor_ids:
        return

    source = _find_editor_account_source(cursor)
    if not source:
        logger.warning("Symantec DLP editor account table could not be discovered")
        return

    owner, table_name, id_column, name_column = map(_safe_identifier, source)
    editor_names: dict[str, str] = {}
    values = list(editor_ids.values())
    for offset in range(0, len(values), 1_000):
        chunk = values[offset:offset + 1_000]
        binds = {f"editor_id_{index}": value for index, value in enumerate(chunk)}
        placeholders = ", ".join(f":{name}" for name in binds)
        cursor.execute(
            f"SELECT {id_column}, {name_column} "
            f"FROM {owner}.{table_name} WHERE {id_column} IN ({placeholders})",
            binds,
        )
        for editor_id, editor_name in cursor.fetchall():
            serialized_name = _serialize_oracle_value(editor_name)
            if serialized_name is not None and str(serialized_name).strip():
                editor_names[str(_serialize_oracle_value(editor_id))] = str(serialized_name).strip()

    for row in rows:
        if row.get("modified_by_id") is not None:
            row["modified_by_name"] = editor_names.get(str(row["modified_by_id"]))


def _query_sync(credentials: dict, max_rows: int) -> tuple[list[dict], bool]:
    import oracledb

    dsn = f"{credentials['db_host']}:{credentials['db_port']}/{credentials['db_name']}"
    connection = oracledb.connect(
        user=credentials["db_user"],
        password=credentials["db_password"],
        dsn=dsn,
    )
    try:
        # Stop a runaway recursive query instead of tying up an API worker.
        connection.call_timeout = 120_000
        cursor = connection.cursor()
        try:
            cursor.arraysize = min(max_rows + 1, 1_000)
            cursor.execute(DLP_POLICY_EXCLUSIONS_SQL)
            columns = [column[0].lower() for column in cursor.description]
            rows = cursor.fetchmany(max_rows + 1)
            truncated = len(rows) > max_rows
            result = [
                {key: _serialize_oracle_value(value) for key, value in zip(columns, row)}
                for row in rows[:max_rows]
            ]
            try:
                _enrich_editor_names(cursor, result)
            except Exception as exc:
                # Account metadata differs between DLP versions. Keep the core
                # policy search available and retain MODIFIED_BY_ID as fallback.
                logger.warning("Symantec DLP editor-name correlation failed: %s", exc)
                for row in result:
                    row.setdefault("modified_by_name", None)
            return result, truncated
        finally:
            cursor.close()
    finally:
        connection.close()


async def query_dlp_policy_exclusions(
    credentials: dict,
    max_rows: int = MAX_DLP_POLICY_ROWS,
) -> tuple[list[dict], bool]:
    """Execute the fixed DLP policy query off the async event loop."""
    return await asyncio.to_thread(_query_sync, credentials, max_rows)
