import asyncio
import logging
from datetime import date, datetime
from decimal import Decimal
from typing import Any

logger = logging.getLogger(__name__)

MAX_DLP_POLICY_ROWS = 10_000

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
            return [
                {key: _serialize_oracle_value(value) for key, value in zip(columns, row)}
                for row in rows[:max_rows]
            ], truncated
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
