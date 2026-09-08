def get_collector_class(integration_type: str):
    """Resolve a collector lazily so optional clients load only when required."""
    if integration_type == "jumpcloud":
        from app.collectors.jumpcloud import JumpCloudCollector

        return JumpCloudCollector
    if integration_type == "puppet":
        from app.collectors.puppet import PuppetCollector

        return PuppetCollector
    if integration_type == "sentinelone":
        from app.collectors.sentinelone import SentinelOneCollector

        return SentinelOneCollector
    if integration_type == "symantec_dlp":
        from app.collectors.symantec import SymantecCollector

        return SymantecCollector
    if integration_type == "google_workspace":
        from app.collectors.google_workspace import GoogleWorkspaceCollector

        return GoogleWorkspaceCollector
    if integration_type == "adfs":
        from app.collectors.adfs import ADFSCollector

        return ADFSCollector
    if integration_type == "active_directory":
        from app.collectors.active_directory import ActiveDirectoryCollector

        return ActiveDirectoryCollector
    if integration_type.startswith("custom_api"):
        from app.collectors.custom_api import CustomApiCollector

        return CustomApiCollector
    if integration_type.startswith("custom_db"):
        from app.collectors.custom_db import CustomDbCollector

        return CustomDbCollector
    return None
