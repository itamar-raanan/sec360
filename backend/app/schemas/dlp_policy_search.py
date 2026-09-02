from datetime import datetime
from typing import Any

from pydantic import BaseModel


class DlpPolicyExclusion(BaseModel):
    object_id: Any = None
    object_name: str | None = None
    object_description: str | None = None
    object_status: str | None = None
    rule_type: Any = None
    used_as: str
    policy_id: Any = None
    policy_name: str | None = None
    policy_active_status: Any = None
    policy_record_status: str | None = None
    user_patterns: str | None = None
    ip_addresses: str | None = None
    url_domains: str | None = None
    personal_email_breadth: Any = None
    personal_email_excluded_domains: str | None = None
    personal_email_max_recipients: Any = None
    modified_date: str | None = None
    modified_by_id: Any = None
    object_uuid: str | None = None


class DlpPolicySearchResponse(BaseModel):
    items: list[DlpPolicyExclusion]
    row_count: int
    max_rows: int
    truncated: bool
    query_duration_ms: int
    source_refreshed_at: datetime
    integration_status: str
