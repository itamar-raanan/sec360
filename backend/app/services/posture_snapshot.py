"""Request-scoped inventory reads for full Compliance and risk evaluation."""

from collections import defaultdict
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import SecurityAgent
from app.models.compliance import ComplianceExclusion, ComplianceStatus
from app.models.endpoint import Endpoint
from app.models.puppet import PuppetNode
from app.models.system_settings import SystemSettings
from app.services.compliance_agents import ComplianceAgent, load_required_compliance_agents
from app.services.endpoint_inventory import current_endpoint_clause


@dataclass
class PostureSnapshot:
    endpoints: dict[UUID, Endpoint]
    agents: dict[UUID, list[SecurityAgent]]
    statuses: dict[UUID, ComplianceStatus]
    exclusions: dict[UUID, set[str]]
    puppet_endpoints: set[UUID]
    settings: SystemSettings | None
    required_agents: tuple[ComplianceAgent, ...]

    def agent_presence(self, endpoint_id: UUID) -> dict[str, bool]:
        products = {agent.product_name for agent in self.agents.get(endpoint_id, [])}
        presence = {
            agent.key: agent.security_agent_product in products
            for agent in self.required_agents
            if agent.security_agent_product
        }
        if any(agent.key == "puppet" for agent in self.required_agents):
            presence["puppet"] = endpoint_id in self.puppet_endpoints
        return presence


async def load_posture_snapshot(
    db: AsyncSession, *, current_only: bool = False,
) -> PostureSnapshot:
    """Load each table once instead of re-querying it for every endpoint.

    This is scoped to the current evaluation, never a cache across syncs.
    Flush first because correlation/compliance may have just changed inventory.
    """
    await db.flush()
    required_agents = await load_required_compliance_agents(db)
    endpoint_ids = select(Endpoint.id)
    endpoint_query = select(Endpoint)
    if current_only:
        endpoint_ids = endpoint_ids.where(current_endpoint_clause())
        endpoint_query = endpoint_query.where(current_endpoint_clause())
    endpoints = {endpoint.id: endpoint for endpoint in (await db.execute(endpoint_query)).scalars()}
    agents = defaultdict(list)
    for agent in (await db.execute(
        select(SecurityAgent).where(SecurityAgent.endpoint_id.in_(endpoint_ids))
    )).scalars():
        agents[agent.endpoint_id].append(agent)
    statuses = {
        status.endpoint_id: status
        for status in (await db.execute(
            select(ComplianceStatus).where(ComplianceStatus.endpoint_id.in_(endpoint_ids))
        )).scalars()
    }
    exclusions = defaultdict(set)
    for endpoint_id, key in (await db.execute(
        select(ComplianceExclusion.endpoint_id, ComplianceExclusion.agent_key)
        .where(ComplianceExclusion.endpoint_id.in_(endpoint_ids))
    )).all():
        exclusions[endpoint_id].add(key)
    puppet_endpoints = set()
    if any(agent.key == "puppet" for agent in required_agents):
        puppet_endpoints = set((await db.execute(
            select(PuppetNode.endpoint_id).distinct().where(PuppetNode.endpoint_id.in_(endpoint_ids))
        )).scalars())
    settings = (await db.execute(
        select(SystemSettings).where(SystemSettings.id == 1)
    )).scalar_one_or_none()
    return PostureSnapshot(
        endpoints=endpoints, agents=dict(agents), statuses=statuses,
        exclusions=dict(exclusions), puppet_endpoints=puppet_endpoints,
        settings=settings, required_agents=required_agents,
    )
