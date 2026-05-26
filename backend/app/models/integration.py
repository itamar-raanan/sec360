import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from app.core.database import Base
from app.core.encryption import EncryptedJSON


class IntegrationConfig(Base):
    __tablename__ = "integration_configs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_type = Column(String(50), unique=True, nullable=False)  # jumpcloud, sentinelone, symantec_dlp, google_workspace, hibob
    display_name = Column(String(100), nullable=False)
    credentials = Column(EncryptedJSON, nullable=True)  # encrypted at rest; set CREDENTIALS_ENCRYPTION_KEY
    is_enabled = Column(Boolean, default=False)
    status = Column(String(20), default="unconfigured")  # unconfigured | connected | error
    last_sync = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    records_synced = Column(String(50), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())
