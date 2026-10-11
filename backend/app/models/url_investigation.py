import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, JSON, LargeBinary, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base
from app.core.encryption import EncryptedJSON


class UrlInvestigation(Base):
    __tablename__ = "url_investigations"
    __table_args__ = (
        Index(
            "uq_url_investigations_active_hash",
            "indicator_hash",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
            sqlite_where=text("status IN ('queued', 'running')"),
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_data = Column(EncryptedJSON, nullable=False)
    indicator_hash = Column(String(64), nullable=False, index=True)
    indicator_preview = Column(String(1000), nullable=False)
    indicator_type = Column(String(20), nullable=False)
    hostname = Column(String(253), nullable=False, index=True)
    registrable_domain = Column(String(253), nullable=False)
    status = Column(String(30), nullable=False, default="queued", index=True)
    is_sensitive = Column(Boolean, nullable=False, default=False)
    sensitive_reasons = Column(JSON, nullable=False, default=list)
    options = Column(JSON, nullable=False, default=dict)
    requested_by_id = Column(UUID(as_uuid=True), ForeignKey("auth_users.id", ondelete="SET NULL"), nullable=True)
    requested_by_email = Column(String(255), nullable=False)
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String(30), nullable=False, default="unknown")
    evidence_confidence = Column(String(20), nullable=False, default="low")
    coverage = Column(JSON, nullable=False, default=dict)
    reasons = Column(JSON, nullable=False, default=list)
    provider_contributions = Column(JSON, nullable=False, default=list)
    scoring_version = Column(String(50), nullable=False, default="url-risk-v1")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    provider_results = relationship(
        "UrlInvestigationProviderResult",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    artifacts = relationship(
        "UrlInvestigationArtifact",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class UrlInvestigationProviderResult(Base):
    __tablename__ = "url_investigation_provider_results"
    __table_args__ = (
        UniqueConstraint("investigation_id", "provider", "operation", name="uq_url_investigation_provider_operation"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(
        UUID(as_uuid=True), ForeignKey("url_investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider = Column(String(60), nullable=False, index=True)
    operation = Column(String(30), nullable=False, default="lookup")
    queried_scope = Column(String(30), nullable=False)
    queried_indicator_preview = Column(String(1000), nullable=False)
    status = Column(String(30), nullable=False, default="queued", index=True)
    native_verdict = Column(String(100), nullable=True)
    native_metrics = Column(JSON, nullable=False, default=dict)
    assessment = Column(JSON, nullable=False, default=dict)
    findings = Column(JSON, nullable=False, default=list)
    evidence = Column(JSON, nullable=False, default=dict)
    report_url = Column(String(2000), nullable=True)
    observed_at = Column(DateTime(timezone=True), nullable=True)
    fetched_at = Column(DateTime(timezone=True), nullable=True)
    cache_status = Column(String(30), nullable=False, default="live")
    error_code = Column(String(80), nullable=True)
    error_message = Column(Text, nullable=True)
    raw_response = Column(EncryptedJSON, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    investigation = relationship("UrlInvestigation", back_populates="provider_results")


class UrlInvestigationArtifact(Base):
    __tablename__ = "url_investigation_artifacts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(
        UUID(as_uuid=True), ForeignKey("url_investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider = Column(String(60), nullable=False)
    artifact_type = Column(String(30), nullable=False, default="screenshot")
    content_type = Column(String(100), nullable=False)
    content = Column(LargeBinary, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    target_data = Column(EncryptedJSON, nullable=False)
    captured_at = Column(DateTime(timezone=True), nullable=False)

    investigation = relationship("UrlInvestigation", back_populates="artifacts")
