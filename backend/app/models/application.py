import uuid
from datetime import datetime, timezone
from sqlalchemy import Float, ForeignKey, Integer, String, DateTime, Enum as SAEnum, JSON, Index, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    type: Mapped[str] = mapped_column(
        SAEnum("saas", "internal", "unknown", name="app_type_enum"), default="saas"
    )
    category: Mapped[str | None] = mapped_column(String(100))
    is_approved: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class RawData(Base):
    __tablename__ = "raw_data"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(100), index=True)
    entity_type: Mapped[str] = mapped_column(String(100))
    raw_json: Mapped[dict] = mapped_column(JSON)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class ApplicationVulnerability(Base):
    """Exact SentinelOne Application Management risk finding."""

    __tablename__ = "application_vulnerabilities"
    __table_args__ = (
        Index("ix_app_vuln_severity_status", "severity", "status"),
        Index("ix_app_vuln_application_endpoint", "application_name", "endpoint_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    sentinelone_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True
    )
    sentinelone_endpoint_id: Mapped[str | None] = mapped_column(String(100), index=True)

    application: Mapped[str] = mapped_column(String(500))
    application_name: Mapped[str] = mapped_column(String(255), index=True)
    application_vendor: Mapped[str | None] = mapped_column(String(500))
    application_version: Mapped[str | None] = mapped_column(String(255))
    cve_id: Mapped[str] = mapped_column(String(50), index=True)
    cvss_version: Mapped[str | None] = mapped_column(String(20))
    nvd_cvss_version: Mapped[str | None] = mapped_column(String(20))
    nvd_base_score: Mapped[float | None] = mapped_column(Float)
    risk_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(20), index=True)

    endpoint_name: Mapped[str] = mapped_column(String(255), index=True)
    endpoint_type: Mapped[str | None] = mapped_column(String(100))
    os_type: Mapped[str | None] = mapped_column(String(50))
    days_detected: Mapped[int | None] = mapped_column(Integer)
    detection_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_result: Mapped[str | None] = mapped_column(String(100))

    exploit_code_maturity: Mapped[str | None] = mapped_column(String(100), index=True)
    remediation_level: Mapped[str | None] = mapped_column(String(100))
    report_confidence: Mapped[str | None] = mapped_column(String(100))
    mitigation_status: Mapped[str | None] = mapped_column(String(100), index=True)
    mitigation_status_change_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    mitigation_status_changed_by: Mapped[str | None] = mapped_column(String(255))
    mitigation_status_reason: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str | None] = mapped_column(String(100), index=True)
    mark_type: Mapped[str | None] = mapped_column(String(100))
    marked_by: Mapped[str | None] = mapped_column(String(255))
    marked_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str | None] = mapped_column(Text)

    raw_json: Mapped[dict] = mapped_column(JSON)
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    endpoint: Mapped["Endpoint | None"] = relationship()  # noqa: F821
