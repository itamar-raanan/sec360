from typing import Final


INTEGRATION_PRODUCTS: Final[tuple[dict, ...]] = (
    {
        "integration_type": "jumpcloud",
        "display_name": "JumpCloud",
        "category": "directory",
        "description": "Directory, identity, and managed-device inventory.",
        "capabilities": ["users", "endpoints", "mfa_status"],
        "features": [],
    },
    {
        "integration_type": "puppet",
        "display_name": "Puppet",
        "category": "infrastructure",
        "description": "PuppetDB node inventory, operating systems, and freshness.",
        "capabilities": ["endpoints", "os_inventory"],
        "features": [],
    },
    {
        "integration_type": "sentinelone",
        "display_name": "SentinelOne",
        "category": "security",
        "description": "Endpoint protection posture and application exposure.",
        "capabilities": ["endpoints", "edr_agents", "application_risks"],
        "features": ["application_vulnerabilities"],
    },
    {
        "integration_type": "symantec_dlp",
        "display_name": "Symantec DLP",
        "category": "data_protection",
        "description": "DLP agent posture and user policy exclusions.",
        "capabilities": ["dlp_agents", "policy_exclusions"],
        "features": ["dlp_policy_search"],
    },
    {
        "integration_type": "google_workspace",
        "display_name": "Google Workspace",
        "category": "productivity",
        "description": "Workspace identities, authentication, and activity events.",
        "capabilities": ["users", "login_events", "oauth_activity"],
        "features": ["activity"],
    },
    {
        "integration_type": "adfs",
        "display_name": "ADFS",
        "category": "directory",
        "description": "Active Directory Federation Services metadata and availability.",
        "capabilities": ["federation_metadata", "service_health"],
        "features": ["activity"],
    },
    {
        "integration_type": "active_directory",
        "display_name": "Active Directory",
        "category": "directory",
        "description": "LDAP users, computers, departments, and ownership context.",
        "capabilities": ["users", "endpoints", "departments"],
        "features": ["activity"],
    },
)

INTEGRATION_DEFAULTS: Final[tuple[tuple[str, str], ...]] = tuple(
    (product["integration_type"], product["display_name"])
    for product in INTEGRATION_PRODUCTS
)

INTEGRATION_TYPES: Final[frozenset[str]] = frozenset(
    product["integration_type"] for product in INTEGRATION_PRODUCTS
)

RETIRED_INTEGRATION_TYPES: Final[tuple[str, ...]] = ("hibob", "cloudsoc")

FEATURE_INTEGRATIONS: Final[dict[str, tuple[str, ...]]] = {
    feature: tuple(
        product["integration_type"]
        for product in INTEGRATION_PRODUCTS
        if feature in product["features"]
    )
    for feature in {
        feature
        for product in INTEGRATION_PRODUCTS
        for feature in product["features"]
    }
}


def catalog_payload() -> list[dict]:
    return [dict(product) for product in INTEGRATION_PRODUCTS]
