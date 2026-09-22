from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.product_scope import load_product_tags


@dataclass(frozen=True)
class ComplianceAgent:
    key: str
    label: str
    integration_type: str
    product_tag: str | None = None
    security_agent_product: str | None = None
    description: str = ""


# This registry is the single extension point for endpoint-producing products.
# Identity-only integrations intentionally do not become endpoint requirements.
COMPLIANCE_AGENTS: tuple[ComplianceAgent, ...] = (
    ComplianceAgent(
        key="sentinelone",
        label="SentinelOne",
        integration_type="sentinelone",
        product_tag="S1",
        security_agent_product="sentinelone",
        description="Endpoint detection and response agent",
    ),
    ComplianceAgent(
        key="symantec_dlp",
        label="Symantec DLP",
        integration_type="symantec_dlp",
        product_tag="DLP",
        security_agent_product="symantec",
        description="Data loss prevention endpoint agent",
    ),
    ComplianceAgent(
        key="symantec_wss",
        label="Symantec WSS",
        integration_type="sentinelone",
        product_tag="WSS",
        security_agent_product="symantec_wss",
        description="Web security agent discovered through SentinelOne",
    ),
    ComplianceAgent(
        key="puppet",
        label="Puppet",
        integration_type="puppet",
        description="Puppet-managed endpoint",
    ),
)

COMPLIANCE_AGENT_BY_KEY = {agent.key: agent for agent in COMPLIANCE_AGENTS}


async def load_required_compliance_agents(db: AsyncSession) -> tuple[ComplianceAgent, ...]:
    """Return configured endpoint-agent requirements in display order.

    A transient sync or health-check error must not remove a product from the
    compliance policy. This intentionally matches the product visibility used
    by the Endpoints page: enabled with saved credentials.
    """
    from app.models.integration import IntegrationConfig

    configured = set((await db.execute(
        select(IntegrationConfig.integration_type).where(
            IntegrationConfig.is_enabled.is_(True),
            IntegrationConfig.credentials.is_not(None),
        )
    )).scalars().all())
    product_tags = set(await load_product_tags(db))
    return tuple(
        agent
        for agent in COMPLIANCE_AGENTS
        if agent.integration_type in configured
        and (agent.product_tag is None or agent.product_tag in product_tags)
    )


async def endpoint_agent_presence(
    endpoint_id,
    security_agents,
    required_agents: tuple[ComplianceAgent, ...],
    db: AsyncSession,
) -> dict[str, bool]:
    """Resolve factual product presence without changing collector data models."""
    products = {agent.product_name for agent in security_agents}
    presence = {
        agent.key: bool(agent.security_agent_product in products)
        for agent in required_agents
        if agent.security_agent_product
    }
    if any(agent.key == "puppet" for agent in required_agents):
        from app.models.puppet import PuppetNode

        presence["puppet"] = bool(await db.scalar(
            select(PuppetNode.certname).where(PuppetNode.endpoint_id == endpoint_id).limit(1)
        ))
    return presence
