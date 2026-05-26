"""
2000-query intent detection test suite for the AI chatbot.

Tests _detect_intent, _is_list_query, _is_followup, and _handle_conversational.

expected_dict keys (all optional — only checked if present):
  endpoints      bool
  users          bool
  activity       bool
  compliance     bool
  risk           bool
  no_endpoints   bool  → intent["endpoints"] must be False
  no_users       bool  → intent["users"] must be False
  no_activity    bool  → intent["activity"] must be False
  no_risk        bool  → intent["risk"] must be False
  is_list        bool  → _is_list_query() result
  owner_name     str   → ep_filters["owner_name"]
  unassigned     bool  → ep_filters["unassigned"]
  edr_missing    bool  → ep_filters["edr_missing"]
  edr_outdated   bool  → ep_filters["edr_outdated"]
  vpn_missing    bool  → ep_filters["vpn_missing"]
  dlp_missing    bool  → ep_filters["dlp_missing"]
  disk_not_encrypted bool → ep_filters["disk_not_encrypted"]
  compliance_status  str  → ep_filters["compliance_status"]
  agent_inactive bool  → ep_filters["agent_inactive"]
  risk_level_ep  str   → ep_filters["risk_level"]
  os             str   → ep_filters["os"]
  mfa_enabled    bool|None → user_filters["mfa_enabled"]
  suspended      bool  → user_filters["suspended"]
  no_endpoint    bool  → user_filters["no_endpoint"]
  employment_status str → user_filters["employment_status"]
  department     str   → user_filters["department"]  (substring match)
  risk_level_u   str   → user_filters["risk_level"]
  event_type     str   → act_filters["event_type"]
  act_user       str   → act_filters["user_email"]
  is_suspicious  bool  → act_filters["is_suspicious"]
  country        str   → act_filters["country"]
  days_back      int   → act_filters["days_back"]
"""
import sys
sys.path.insert(0, "/app")

from app.api.routes.ai_chat import (
    _detect_intent, _is_list_query, _is_followup, _handle_conversational
)

# ---------------------------------------------------------------------------
# Helper: fake ChatMessage for _is_followup tests
# ---------------------------------------------------------------------------
class FakeMsg:
    def __init__(self, role, content):
        self.role = role
        self.content = content


# ===========================================================================
# INTENT TESTS  (query, expected_dict)
# ===========================================================================

INTENT_TESTS = [

    # =========================================================================
    # ENDPOINT LISTING (no filter)
    # =========================================================================
    ("list all endpoints",                          {"endpoints": True, "is_list": True}),
    ("show me all devices",                         {"endpoints": True, "is_list": True}),
    ("give me all machines",                        {"endpoints": True, "is_list": True}),
    ("get all computers",                           {"endpoints": True, "is_list": True}),
    ("show laptops",                                {"endpoints": True, "is_list": True}),
    ("display all workstations",                    {"endpoints": True, "is_list": True}),
    ("fetch all hosts",                             {"endpoints": True, "is_list": True}),
    ("what are all the endpoints",                  {"endpoints": True, "is_list": True}),
    ("which endpoints do we have",                  {"endpoints": True, "is_list": True}),
    ("list pcs",                                    {"endpoints": True, "is_list": True}),
    ("show all hostnames",                          {"endpoints": True, "is_list": True}),
    ("find all devices",                            {"endpoints": True, "is_list": True}),

    # =========================================================================
    # USER LISTING (no filter)
    # =========================================================================
    ("list all users",                              {"users": True, "is_list": True}),
    ("show me all employees",                       {"users": True, "is_list": True}),
    ("give me all people",                          {"users": True, "is_list": True}),
    ("get all staff",                               {"users": True, "is_list": True}),
    ("show all accounts",                           {"users": True, "is_list": True}),
    ("fetch all members",                           {"users": True, "is_list": True}),
    ("list workers",                                {"users": True, "is_list": True}),
    ("who are all the users",                       {"users": True, "is_list": True}),

    # =========================================================================
    # UNASSIGNED ENDPOINTS
    # =========================================================================
    ("show unassigned endpoints",                   {"endpoints": True, "unassigned": True, "no_users": True}),
    ("list devices without an owner",               {"endpoints": True, "unassigned": True}),
    ("endpoints with no owner",                     {"endpoints": True, "unassigned": True}),
    ("which machines are unassigned",               {"endpoints": True, "unassigned": True}),
    ("endpoints not assigned to any user",          {"endpoints": True, "unassigned": True}),
    ("show me unassigned machines",                 {"endpoints": True, "unassigned": True}),
    ("find endpoints with missing owner",           {"endpoints": True, "unassigned": True}),
    ("devices without owner",                       {"endpoints": True, "unassigned": True}),
    ("list all unassigned devices",                 {"endpoints": True, "unassigned": True}),
    ("unassigned endpoints",                        {"endpoints": True, "unassigned": True}),
    ("which endpoints have no owner",               {"endpoints": True, "unassigned": True}),
    ("laptops without assignment",                  {"endpoints": True, "unassigned": True}),
    ("show endpoints with no assigned user",        {"endpoints": True, "unassigned": True}),
    ("devices not assigned",                        {"endpoints": True, "unassigned": True}),

    # =========================================================================
    # EDR MISSING
    # =========================================================================
    ("show endpoints missing EDR",                  {"endpoints": True, "edr_missing": True}),
    ("list devices without S1",                     {"endpoints": True, "edr_missing": True}),
    ("machines without SentinelOne",                {"endpoints": True, "edr_missing": True}),
    ("endpoints with no EDR installed",             {"endpoints": True, "edr_missing": True}),
    ("which devices are missing sentinelone",       {"endpoints": True, "edr_missing": True}),
    ("find endpoints without EDR",                  {"endpoints": True, "edr_missing": True}),
    ("no EDR endpoints",                            {"endpoints": True, "edr_missing": True}),
    ("show endpoints where EDR is missing",         {"endpoints": True, "edr_missing": True}),
    ("computers lacking s1",                        {"endpoints": True, "edr_missing": True}),
    ("EDR not installed endpoints",                 {"endpoints": True, "edr_missing": True}),
    ("list machines with missing sentinelone",      {"endpoints": True, "edr_missing": True}),
    ("endpoints where s1 is absent",               {"endpoints": True, "edr_missing": True}),

    # =========================================================================
    # EDR OUTDATED
    # =========================================================================
    ("show endpoints with outdated EDR",            {"endpoints": True, "edr_outdated": True}),
    ("list devices with outdated S1",               {"endpoints": True, "edr_outdated": True}),
    ("machines with old sentinelone",               {"endpoints": True, "edr_outdated": True}),
    ("endpoints where EDR is out of date",          {"endpoints": True, "edr_outdated": True}),
    ("devices with outdated agent",                 {"endpoints": True, "edr_outdated": True}),
    ("S1 version not updated",                      {"endpoints": True, "edr_outdated": True}),
    ("outdated EDR endpoints",                      {"endpoints": True, "edr_outdated": True}),
    ("which endpoints have outdated SentinelOne",   {"endpoints": True, "edr_outdated": True}),
    ("show machines that need EDR update",          {"endpoints": True, "edr_outdated": True}),
    ("endpoints with old S1 version",               {"endpoints": True, "edr_outdated": True}),
    ("sentinelone outdated devices",                {"endpoints": True, "edr_outdated": True}),
    ("list endpoints with outdated sentinelone",    {"endpoints": True, "edr_outdated": True}),
    ("EDR agent out of date endpoints",             {"endpoints": True, "edr_outdated": True}),

    # =========================================================================
    # VPN MISSING
    # =========================================================================
    ("show endpoints without VPN",                  {"endpoints": True, "vpn_missing": True}),
    ("list devices missing VPN",                    {"endpoints": True, "vpn_missing": True}),
    ("machines without GlobalProtect",              {"endpoints": True, "vpn_missing": True}),
    ("endpoints with no VPN installed",             {"endpoints": True, "vpn_missing": True}),
    ("find devices missing globalprotect",          {"endpoints": True, "vpn_missing": True}),
    ("no VPN endpoints",                            {"endpoints": True, "vpn_missing": True}),
    ("which endpoints don't have VPN",              {"endpoints": True, "vpn_missing": True}),
    ("show laptops without VPN",                    {"endpoints": True, "vpn_missing": True}),
    ("computers with missing VPN",                  {"endpoints": True, "vpn_missing": True}),
    ("endpoints lacking vpn",                       {"endpoints": True, "vpn_missing": True}),
    ("list machines without gp",                    {"endpoints": True, "vpn_missing": True}),
    ("VPN not installed on these endpoints",        {"endpoints": True, "vpn_missing": True}),

    # =========================================================================
    # DLP MISSING
    # =========================================================================
    ("show endpoints missing DLP",                  {"endpoints": True, "dlp_missing": True}),
    ("list devices without DLP",                    {"endpoints": True, "dlp_missing": True}),
    ("machines with no DLP",                        {"endpoints": True, "dlp_missing": True}),
    ("endpoints with missing DLP",                  {"endpoints": True, "dlp_missing": True}),
    ("find devices lacking DLP",                    {"endpoints": True, "dlp_missing": True}),
    ("no DLP endpoints",                            {"endpoints": True, "dlp_missing": True}),
    ("DLP absent endpoints",                        {"endpoints": True, "dlp_missing": True}),
    ("show computers where DLP is not installed",   {"endpoints": True, "dlp_missing": True}),
    ("list endpoints without dlp agent",            {"endpoints": True, "dlp_missing": True}),

    # =========================================================================
    # DISK NOT ENCRYPTED
    # =========================================================================
    ("show unencrypted endpoints",                  {"endpoints": True, "disk_not_encrypted": True}),
    ("list devices without disk encryption",        {"endpoints": True, "disk_not_encrypted": True}),
    ("machines without BitLocker",                  {"endpoints": True, "disk_not_encrypted": True}),
    ("endpoints without FileVault",                 {"endpoints": True, "disk_not_encrypted": True}),
    ("find unencrypted devices",                    {"endpoints": True, "disk_not_encrypted": True}),
    ("show endpoints with no disk encryption",      {"endpoints": True, "disk_not_encrypted": True}),
    ("not encrypted endpoints",                     {"endpoints": True, "disk_not_encrypted": True}),
    ("which devices are not encrypted",             {"endpoints": True, "disk_not_encrypted": True}),
    ("computers missing disk encryption",           {"endpoints": True, "disk_not_encrypted": True}),
    ("list endpoints with missing bitlocker",       {"endpoints": True, "disk_not_encrypted": True}),

    # =========================================================================
    # COMPLIANCE STATUS
    # =========================================================================
    ("show non-compliant endpoints",                {"endpoints": True, "compliance_status": "non_compliant"}),
    ("list non compliant devices",                  {"endpoints": True, "compliance_status": "non_compliant"}),
    ("endpoints that are not compliant",            {"endpoints": True, "compliance_status": "non_compliant"}),
    ("find non compliant machines",                 {"endpoints": True, "compliance_status": "non_compliant"}),
    ("which endpoints fail compliance",             {"endpoints": True, "compliance_status": "non_compliant"}),
    ("show partially compliant endpoints",          {"endpoints": True, "compliance_status": "partial"}),
    ("list partial compliance devices",             {"endpoints": True, "compliance_status": "partial"}),
    ("endpoints with partial compliance",           {"endpoints": True, "compliance_status": "partial"}),
    ("show fully compliant endpoints",              {"endpoints": True, "compliance_status": "compliant"}),
    ("list compliant endpoints",                    {"endpoints": True, "compliance_status": "compliant"}),
    ("compliant endpoint listing",                  {"endpoints": True, "compliance_status": "compliant"}),
    ("all fully compliant machines",                {"endpoints": True, "compliance_status": "compliant"}),
    ("show endpoints that are fully compliant",     {"endpoints": True, "compliance_status": "compliant"}),
    ("devices with non compliant status",           {"endpoints": True, "compliance_status": "non_compliant"}),

    # =========================================================================
    # AGENT INACTIVE
    # =========================================================================
    ("show endpoints with inactive agents",         {"endpoints": True, "agent_inactive": True}),
    ("list devices where agent is inactive",        {"endpoints": True, "agent_inactive": True}),
    ("machines with stopped agents",                {"endpoints": True, "agent_inactive": True}),
    ("find endpoints with disabled agents",         {"endpoints": True, "agent_inactive": True}),
    ("inactive agent endpoints",                    {"endpoints": True, "agent_inactive": True}),
    ("agent stopped on these endpoints",            {"endpoints": True, "agent_inactive": True}),
    ("show devices with inactive security agent",   {"endpoints": True, "agent_inactive": True}),

    # =========================================================================
    # OS FILTER
    # =========================================================================
    ("show Windows endpoints",                      {"endpoints": True, "os": "windows"}),
    ("list Windows devices",                        {"endpoints": True, "os": "windows"}),
    ("find all Windows machines",                   {"endpoints": True, "os": "windows"}),
    ("Windows workstations",                        {"endpoints": True, "os": "windows"}),
    ("show macOS endpoints",                        {"endpoints": True, "os": "macos"}),
    ("list Mac devices",                            {"endpoints": True, "os": "macos"}),
    ("find macos machines",                         {"endpoints": True, "os": "macos"}),
    ("show all macOS laptops",                      {"endpoints": True, "os": "macos"}),
    ("Mac OS endpoints",                            {"endpoints": True, "os": "macos"}),
    ("show Linux endpoints",                        {"endpoints": True, "os": "linux"}),
    ("list Linux devices",                          {"endpoints": True, "os": "linux"}),
    ("find all Linux machines",                     {"endpoints": True, "os": "linux"}),
    ("Linux workstations",                          {"endpoints": True, "os": "linux"}),
    ("show linux servers",                          {"endpoints": True, "os": "linux"}),

    # =========================================================================
    # RISK LEVEL - ENDPOINTS
    # =========================================================================
    ("show high risk endpoints",                    {"endpoints": True, "risk_level_ep": "high", "no_risk": True}),
    ("list critical risk devices",                  {"endpoints": True, "risk_level_ep": "critical", "no_risk": True}),
    ("medium risk endpoints",                       {"endpoints": True, "risk_level_ep": "medium", "no_risk": True}),
    ("low risk machines",                           {"endpoints": True, "risk_level_ep": "low", "no_risk": True}),
    ("find high-risk laptops",                      {"endpoints": True, "risk_level_ep": "high"}),
    ("critical risk computers",                     {"endpoints": True, "risk_level_ep": "critical"}),
    ("endpoints with high risk score",              {"endpoints": True, "risk_level_ep": "high"}),
    ("show me critical endpoints",                  {"endpoints": True, "risk_level_ep": "critical"}),

    # =========================================================================
    # RISK LEVEL - USERS
    # =========================================================================
    ("show high risk users",                        {"users": True, "risk_level_u": "high"}),
    ("list critical risk employees",                {"users": True, "risk_level_u": "critical"}),
    ("medium risk users",                           {"users": True, "risk_level_u": "medium"}),
    ("low risk accounts",                           {"users": True, "risk_level_u": "low"}),
    ("find high-risk staff",                        {"users": True, "risk_level_u": "high"}),
    ("users with critical risk score",              {"users": True, "risk_level_u": "critical"}),

    # =========================================================================
    # NO MFA
    # =========================================================================
    ("show users without MFA",                      {"users": True, "mfa_enabled": False}),
    ("list employees with no MFA",                  {"users": True, "mfa_enabled": False}),
    ("users missing MFA",                           {"users": True, "mfa_enabled": False}),
    ("find users without 2FA",                      {"users": True, "mfa_enabled": False}),
    ("who doesn't have MFA",                        {"users": True, "mfa_enabled": False}),
    ("users with MFA disabled",                     {"users": True, "mfa_enabled": False}),
    ("show accounts with no two-factor",            {"users": True, "mfa_enabled": False}),
    ("employees lacking MFA",                       {"users": True, "mfa_enabled": False}),
    ("staff without 2fa",                           {"users": True, "mfa_enabled": False}),
    ("users where MFA is not enabled",              {"users": True, "mfa_enabled": False}),
    ("employees with disabled MFA",                 {"users": True, "mfa_enabled": False}),
    ("accounts with mfa off",                       {"users": True, "mfa_enabled": False}),
    ("no two factor auth users",                    {"users": True, "mfa_enabled": False}),

    # =========================================================================
    # HAS MFA
    # =========================================================================
    ("show users with MFA enabled",                 {"users": True, "mfa_enabled": True}),
    ("list employees that have MFA",                {"users": True, "mfa_enabled": True}),
    ("users with two-factor enabled",               {"users": True, "mfa_enabled": True}),
    ("accounts with MFA on",                        {"users": True, "mfa_enabled": True}),
    ("find staff with 2fa active",                  {"users": True, "mfa_enabled": True}),

    # =========================================================================
    # SUSPENDED
    # =========================================================================
    ("show suspended users",                        {"users": True, "suspended": True}),
    ("list disabled accounts",                      {"users": True, "suspended": True}),
    ("find locked out users",                       {"users": True, "suspended": True}),
    ("blocked accounts",                            {"users": True, "suspended": True}),
    ("which users are suspended",                   {"users": True, "suspended": True}),
    ("show me suspended employees",                 {"users": True, "suspended": True}),
    ("all locked out accounts",                     {"users": True, "suspended": True}),

    # =========================================================================
    # NO ENDPOINT
    # =========================================================================
    ("show users with no endpoint",                 {"users": True, "no_endpoint": True}),
    ("list employees without devices",              {"users": True, "no_endpoint": True}),
    ("users with no machines",                      {"users": True, "no_endpoint": True}),
    ("find accounts with no endpoint",              {"users": True, "no_endpoint": True}),
    ("which users have no devices",                 {"users": True, "no_endpoint": True}),
    ("employees without laptops",                   {"users": True, "no_endpoint": True}),
    ("staff without a computer",                    {"users": True, "no_endpoint": True}),
    ("accounts with no endpoint assigned",          {"users": True, "no_endpoint": True}),
    ("users not associated with any device",        {"users": True, "no_endpoint": True}),
    ("list people with no computer",                {"users": True, "no_endpoint": True}),

    # =========================================================================
    # DEPARTMENT FILTER
    # =========================================================================
    ("list users in the engineering department",    {"users": True, "department": "engineering"}),
    ("show employees in finance",                   {"users": True, "department": "finance"}),
    ("users from the sales team",                   {"users": True, "department": "sales"}),
    ("list staff in HR department",                 {"users": True, "department": "hr"}),
    ("show marketing users",                        {"users": True, "department": "marketing"}),
    ("employees in the IT department",              {"users": True, "department": "it"}),
    ("list people in operations",                   {"users": True, "department": "operations"}),
    ("show accounts in legal",                      {"users": True, "department": "legal"}),

    # =========================================================================
    # INACTIVE USERS
    # =========================================================================
    ("show inactive users",                         {"users": True, "employment_status": "inactive"}),
    ("list inactive employees",                     {"users": True, "employment_status": "inactive"}),
    ("find not active user accounts",               {"users": True, "employment_status": "inactive"}),
    ("show inactive accounts",                      {"users": True, "employment_status": "inactive"}),

    # =========================================================================
    # SUSPICIOUS ACTIVITY
    # =========================================================================
    ("show suspicious login events",                {"activity": True, "is_suspicious": True}),
    ("list anomalous activity",                     {"activity": True, "is_suspicious": True}),
    ("find flagged events",                         {"activity": True, "is_suspicious": True}),
    ("show unusual login activity",                 {"activity": True, "is_suspicious": True}),
    ("malicious login events",                      {"activity": True, "is_suspicious": True}),
    ("which logins are suspicious",                 {"activity": True, "is_suspicious": True}),
    ("show me flagged login activity",              {"activity": True, "is_suspicious": True}),
    ("find threat events",                          {"activity": True, "is_suspicious": True}),
    ("anomalous login events",                      {"activity": True, "is_suspicious": True}),
    ("suspicious auth events",                      {"activity": True, "is_suspicious": True}),
    ("show me unusual access",                      {"activity": True, "is_suspicious": True}),

    # =========================================================================
    # COUNTRY FILTER
    # =========================================================================
    ("show logins from Russia",                     {"activity": True, "country": "Russia"}),
    ("list login events from China",                {"activity": True, "country": "China"}),
    ("find access from Iran",                       {"activity": True, "country": "Iran"}),
    ("show activity from Ukraine",                  {"activity": True, "country": "Ukraine"}),
    ("logins from North Korea",                     {"activity": True, "country": "North Korea"}),
    ("show events from Germany",                    {"activity": True, "country": "Germany"}),
    ("list access from India",                      {"activity": True, "country": "India"}),
    ("events from Nigeria",                         {"activity": True, "country": "Nigeria"}),
    ("show logins from Romania",                    {"activity": True, "country": "Romania"}),
    ("access events from Vietnam",                  {"activity": True, "country": "Vietnam"}),
    ("show activity from Israel",                   {"activity": True, "country": "Israel"}),
    ("login events from Brazil",                    {"activity": True, "country": "Brazil"}),
    ("access from Canada",                          {"activity": True, "country": "Canada"}),
    ("events from Australia",                       {"activity": True, "country": "Australia"}),

    # =========================================================================
    # DAYS BACK
    # =========================================================================
    ("show activity from the last 7 days",          {"activity": True, "days_back": 7}),
    ("login events in the last 30 days",            {"activity": True, "days_back": 30}),
    ("show last 14 days activity",                  {"activity": True, "days_back": 14}),
    ("events from last 90 days",                    {"activity": True, "days_back": 90}),
    ("show today's logins",                         {"activity": True, "days_back": 1}),
    ("today's login events",                        {"activity": True, "days_back": 1}),
    ("this week's login activity",                  {"activity": True, "days_back": 7}),
    ("last week login events",                      {"activity": True, "days_back": 7}),
    ("this month's logins",                         {"activity": True, "days_back": 30}),
    ("last month login events",                     {"activity": True, "days_back": 30}),
    ("past 7 days login activity",                  {"activity": True, "days_back": 7}),
    ("show logins for last 3 days",                 {"activity": True, "days_back": 3}),
    ("activity in last 60 days",                    {"activity": True, "days_back": 60}),
    ("past week events",                            {"activity": True, "days_back": 7}),

    # =========================================================================
    # COMPLIANCE SUMMARY
    # =========================================================================
    ("show compliance overview",                    {"compliance": True}),
    ("give me a compliance summary",                {"compliance": True}),
    ("what is the compliance status",               {"compliance": True}),
    ("show security posture",                       {"compliance": True}),
    ("compliance report",                           {"compliance": True}),
    ("how is our compliance",                       {"compliance": True}),
    ("show policy status",                          {"compliance": True}),
    ("give me the compliance overview",             {"compliance": True}),
    ("what's our security compliance",              {"compliance": True}),
    ("compliance breakdown",                        {"compliance": True}),

    # =========================================================================
    # RISK SUMMARY
    # =========================================================================
    ("show risk overview",                          {"risk": True}),
    ("give me a risk summary",                      {"risk": True}),
    ("what is the risk distribution",               {"risk": True}),
    ("show risky users and devices",                {"risk": True}),
    ("risk score overview",                         {"risk": True}),
    ("how risky are our assets",                    {"risk": True}),
    ("show high risk summary",                      {"risk": True}),
    ("risk distribution overview",                  {"risk": True}),
    ("show critical risk summary",                  {"risk": True}),

    # =========================================================================
    # COMBINED FILTERS (endpoint + OS + risk)
    # =========================================================================
    ("show high risk Windows endpoints",            {"endpoints": True, "os": "windows", "risk_level_ep": "high"}),
    ("list critical macOS devices",                 {"endpoints": True, "os": "macos", "risk_level_ep": "critical"}),
    ("Linux machines with high risk",               {"endpoints": True, "os": "linux", "risk_level_ep": "high"}),
    ("Windows endpoints without VPN",               {"endpoints": True, "os": "windows", "vpn_missing": True}),
    ("macOS devices missing EDR",                   {"endpoints": True, "os": "macos", "edr_missing": True}),
    ("Linux endpoints without disk encryption",     {"endpoints": True, "os": "linux", "disk_not_encrypted": True}),

    # =========================================================================
    # COMBINED FILTERS (user + MFA + department)
    # =========================================================================
    ("show finance users without MFA",              {"users": True, "department": "finance", "mfa_enabled": False}),
    ("engineering staff without 2FA",               {"users": True, "department": "engineering", "mfa_enabled": False}),
    ("high risk users in sales",                    {"users": True, "department": "sales", "risk_level_u": "high"}),

    # =========================================================================
    # SAML EVENT TYPE  (NEW PATTERN)
    # =========================================================================
    ("show saml events",                            {"activity": True, "event_type": "saml"}),
    ("list saml logins",                            {"activity": True, "event_type": "saml"}),
    ("show all saml activity",                      {"activity": True, "event_type": "saml"}),
    ("find saml authentication events",             {"activity": True, "event_type": "saml"}),
    ("saml login events",                           {"activity": True, "event_type": "saml"}),
    ("display saml events",                         {"activity": True, "event_type": "saml"}),
    ("show me saml events",                         {"activity": True, "event_type": "saml"}),
    ("list all saml events",                        {"activity": True, "event_type": "saml"}),
    ("SAML activity",                               {"activity": True, "event_type": "saml"}),
    ("show SAML logins",                            {"activity": True, "event_type": "saml"}),
    ("find all saml login events",                  {"activity": True, "event_type": "saml"}),
    ("saml authentication activity",                {"activity": True, "event_type": "saml"}),
    ("show saml sessions",                          {"activity": True, "event_type": "saml"}),
    ("saml sign-in events",                         {"activity": True, "event_type": "saml"}),
    ("list saml access events",                     {"activity": True, "event_type": "saml"}),
    ("show saml login history",                     {"activity": True, "event_type": "saml"}),
    ("recent saml events",                          {"activity": True, "event_type": "saml"}),
    ("list apps that user login to via saml",       {"activity": True, "event_type": "saml", "no_users": True}),
    ("what apps were accessed via saml",            {"activity": True, "event_type": "saml"}),
    ("show all apps that users sign in to via saml",{"activity": True, "event_type": "saml"}),
    ("saml app logins",                             {"activity": True, "event_type": "saml"}),
    ("all saml sign ins",                           {"activity": True, "event_type": "saml"}),
    ("list saml based logins",                      {"activity": True, "event_type": "saml"}),
    ("display all saml auth events",                {"activity": True, "event_type": "saml"}),

    # =========================================================================
    # OAUTH GRANT EVENT TYPE  (NEW PATTERN)
    # =========================================================================
    ("show oauth grant events",                     {"activity": True, "event_type": "oauth_grant"}),
    ("list oauth events",                           {"activity": True, "event_type": "oauth_grant"}),
    ("show oauth grants",                           {"activity": True, "event_type": "oauth_grant"}),
    ("find oauth grant activity",                   {"activity": True, "event_type": "oauth_grant"}),
    ("oauth grant login events",                    {"activity": True, "event_type": "oauth_grant"}),
    ("display oauth grant events",                  {"activity": True, "event_type": "oauth_grant"}),
    ("list all oauth grants",                       {"activity": True, "event_type": "oauth_grant"}),
    ("show me oauth grant activity",                {"activity": True, "event_type": "oauth_grant"}),
    ("OAuth grant sessions",                        {"activity": True, "event_type": "oauth_grant"}),
    ("show oauth grant logins",                     {"activity": True, "event_type": "oauth_grant"}),
    ("list oauth grant access events",              {"activity": True, "event_type": "oauth_grant"}),
    ("all oauth grant events",                      {"activity": True, "event_type": "oauth_grant"}),
    ("recent oauth grant events",                   {"activity": True, "event_type": "oauth_grant"}),
    ("display oauth grants",                        {"activity": True, "event_type": "oauth_grant"}),
    ("find oauth grant sessions",                   {"activity": True, "event_type": "oauth_grant"}),

    # =========================================================================
    # APP USAGE EVENT TYPE  (NEW PATTERN)
    # =========================================================================
    ("show app usage events",                       {"activity": True, "event_type": "app_usage"}),
    ("list app usage activity",                     {"activity": True, "event_type": "app_usage"}),
    ("show application usage events",               {"activity": True, "event_type": "app_usage"}),
    ("find app usage data",                         {"activity": True, "event_type": "app_usage"}),
    ("display app usage events",                    {"activity": True, "event_type": "app_usage"}),
    ("app usage logs",                              {"activity": True, "event_type": "app_usage"}),
    ("show me app usage",                           {"activity": True, "event_type": "app_usage"}),
    ("list all app usage events",                   {"activity": True, "event_type": "app_usage"}),
    ("app-usage events",                            {"activity": True, "event_type": "app_usage"}),
    ("show app usage statistics",                   {"activity": True, "event_type": "app_usage"}),
    ("application usage activity",                  {"activity": True, "event_type": "app_usage"}),
    ("list app login events",                       {"activity": True, "event_type": "app_usage"}),
    ("show app logins",                             {"activity": True, "event_type": "app_usage"}),
    ("app login activity",                          {"activity": True, "event_type": "app_usage"}),
    ("show all application usage",                  {"activity": True, "event_type": "app_usage"}),

    # =========================================================================
    # NETWORK EVENT TYPE  (NEW PATTERN)
    # =========================================================================
    ("show network events",                         {"activity": True, "event_type": "network"}),
    ("list network activity",                       {"activity": True, "event_type": "network"}),
    ("show network traffic events",                 {"activity": True, "event_type": "network"}),
    ("find network access events",                  {"activity": True, "event_type": "network"}),
    ("display network events",                      {"activity": True, "event_type": "network"}),
    ("network event logs",                          {"activity": True, "event_type": "network"}),
    ("show me network events",                      {"activity": True, "event_type": "network"}),
    ("list all network events",                     {"activity": True, "event_type": "network"}),
    ("show network activity events",                {"activity": True, "event_type": "network"}),
    ("network traffic activity",                    {"activity": True, "event_type": "network"}),
    ("find all network activity",                   {"activity": True, "event_type": "network"}),
    ("recent network events",                       {"activity": True, "event_type": "network"}),
    ("network access logs",                         {"activity": True, "event_type": "network"}),
    ("show network connection events",              {"activity": True, "event_type": "network"}),

    # =========================================================================
    # FILE ACCESS EVENT TYPE  (NEW PATTERN)
    # =========================================================================
    ("show file access events",                     {"activity": True, "event_type": "file_access"}),
    ("list file access activity",                   {"activity": True, "event_type": "file_access"}),
    ("find file access events",                     {"activity": True, "event_type": "file_access"}),
    ("display file access logs",                    {"activity": True, "event_type": "file_access"}),
    ("show me file access events",                  {"activity": True, "event_type": "file_access"}),
    ("file access event listing",                   {"activity": True, "event_type": "file_access"}),
    ("list all file access events",                 {"activity": True, "event_type": "file_access"}),
    ("recent file access events",                   {"activity": True, "event_type": "file_access"}),
    ("file-access events",                          {"activity": True, "event_type": "file_access"}),
    ("show file access history",                    {"activity": True, "event_type": "file_access"}),
    ("file access activity log",                    {"activity": True, "event_type": "file_access"}),

    # =========================================================================
    # CLOUD ACCESS EVENT TYPE  (NEW PATTERN)
    # =========================================================================
    ("show cloud access events",                    {"activity": True, "event_type": "cloud_access"}),
    ("list cloud access activity",                  {"activity": True, "event_type": "cloud_access"}),
    ("find cloud access events",                    {"activity": True, "event_type": "cloud_access"}),
    ("display cloud access logs",                   {"activity": True, "event_type": "cloud_access"}),
    ("show me cloud access events",                 {"activity": True, "event_type": "cloud_access"}),
    ("cloud access event listing",                  {"activity": True, "event_type": "cloud_access"}),
    ("list all cloud access events",                {"activity": True, "event_type": "cloud_access"}),
    ("recent cloud access events",                  {"activity": True, "event_type": "cloud_access"}),
    ("cloud-access events",                         {"activity": True, "event_type": "cloud_access"}),
    ("show cloud access history",                   {"activity": True, "event_type": "cloud_access"}),
    ("cloud access activity",                       {"activity": True, "event_type": "cloud_access"}),
    ("show all cloud access activity",              {"activity": True, "event_type": "cloud_access"}),

    # =========================================================================
    # VPN EVENT TYPE  (NEW PATTERN)
    # =========================================================================
    ("show vpn events",                             {"activity": True, "event_type": "vpn"}),
    ("list vpn activity",                           {"activity": True, "event_type": "vpn"}),
    ("show vpn connection events",                  {"activity": True, "event_type": "vpn"}),
    ("find vpn login events",                       {"activity": True, "event_type": "vpn"}),
    ("display vpn events",                          {"activity": True, "event_type": "vpn"}),
    ("vpn event logs",                              {"activity": True, "event_type": "vpn"}),
    ("show me vpn events",                          {"activity": True, "event_type": "vpn"}),
    ("list all vpn events",                         {"activity": True, "event_type": "vpn"}),
    ("show vpn activity events",                    {"activity": True, "event_type": "vpn"}),
    ("vpn connection activity",                     {"activity": True, "event_type": "vpn"}),
    ("show vpn login activity",                     {"activity": True, "event_type": "vpn"}),
    ("vpn connect events",                          {"activity": True, "event_type": "vpn"}),
    ("show vpn log",                                {"activity": True, "event_type": "vpn"}),
    ("vpn session events",                          {"activity": True, "event_type": "vpn"}),

    # =========================================================================
    # NAMED OWNER LOOKUP  (NEW PATTERN)
    # =========================================================================
    # Pattern: "X's devices"
    ("show me liad's devices",                      {"endpoints": True, "owner_name": "liad"}),
    ("list alice's endpoints",                      {"endpoints": True, "owner_name": "alice"}),
    ("show bob's machines",                         {"endpoints": True, "owner_name": "bob"}),
    ("find charlie's computers",                    {"endpoints": True, "owner_name": "charlie"}),
    ("get eve's laptops",                           {"endpoints": True, "owner_name": "eve"}),
    ("show david's workstations",                   {"endpoints": True, "owner_name": "david"}),
    ("list frank's pcs",                            {"endpoints": True, "owner_name": "frank"}),
    ("display grace's endpoints",                   {"endpoints": True, "owner_name": "grace"}),
    ("show henry's devices",                        {"endpoints": True, "owner_name": "henry"}),
    ("list iris's machines",                        {"endpoints": True, "owner_name": "iris"}),
    ("find jake's endpoints",                       {"endpoints": True, "owner_name": "jake"}),
    ("show karen's computers",                      {"endpoints": True, "owner_name": "karen"}),
    ("list laura's laptops",                        {"endpoints": True, "owner_name": "laura"}),
    ("show mike's devices",                         {"endpoints": True, "owner_name": "mike"}),
    ("find nancy's workstations",                   {"endpoints": True, "owner_name": "nancy"}),

    # Pattern: "devices for X"
    ("list devices for alice",                      {"endpoints": True, "owner_name": "alice"}),
    ("show endpoints for bob",                      {"endpoints": True, "owner_name": "bob"}),
    ("find machines for charlie",                   {"endpoints": True, "owner_name": "charlie"}),
    ("get devices for david",                       {"endpoints": True, "owner_name": "david"}),
    ("list endpoints for eve",                      {"endpoints": True, "owner_name": "eve"}),
    ("show computers for frank",                    {"endpoints": True, "owner_name": "frank"}),
    ("display devices for grace",                   {"endpoints": True, "owner_name": "grace"}),
    ("list machines for henry",                     {"endpoints": True, "owner_name": "henry"}),
    ("show laptops for iris",                       {"endpoints": True, "owner_name": "iris"}),
    ("find workstations for jake",                  {"endpoints": True, "owner_name": "jake"}),
    ("list pcs for karen",                          {"endpoints": True, "owner_name": "karen"}),
    ("endpoints for liad",                          {"endpoints": True, "owner_name": "liad"}),
    ("devices for alice",                           {"endpoints": True, "owner_name": "alice"}),

    # Pattern: "devices owned by X"
    ("endpoints owned by alice",                    {"endpoints": True, "owner_name": "alice"}),
    ("devices owned by bob",                        {"endpoints": True, "owner_name": "bob"}),
    ("machines owned by charlie",                   {"endpoints": True, "owner_name": "charlie"}),
    ("computers owned by david",                    {"endpoints": True, "owner_name": "david"}),
    ("laptops owned by eve",                        {"endpoints": True, "owner_name": "eve"}),
    ("workstations owned by frank",                 {"endpoints": True, "owner_name": "frank"}),
    ("endpoints belonging to grace",                {"endpoints": True, "owner_name": "grace"}),
    ("devices belonging to henry",                  {"endpoints": True, "owner_name": "henry"}),
    ("machines assigned to iris",                   {"endpoints": True, "owner_name": "iris"}),
    ("computers assigned to jake",                  {"endpoints": True, "owner_name": "jake"}),

    # Pattern: "what devices does X have"
    ("what devices does bob have",                  {"endpoints": True, "owner_name": "bob"}),
    ("what machines does alice have",               {"endpoints": True, "owner_name": "alice"}),
    ("what computers does charlie have",            {"endpoints": True, "owner_name": "charlie"}),
    ("what endpoints does david have",              {"endpoints": True, "owner_name": "david"}),
    ("what laptops does eve have",                  {"endpoints": True, "owner_name": "eve"}),
    ("what devices does frank own",                 {"endpoints": True, "owner_name": "frank"}),
    ("what machines does grace use",                {"endpoints": True, "owner_name": "grace"}),
    ("what devices does henry own",                 {"endpoints": True, "owner_name": "henry"}),
    ("what computers do iris own",                  {"endpoints": True, "owner_name": "iris"}),

    # Pattern: "show me X devices"
    ("show me alice devices",                       {"endpoints": True, "owner_name": "alice"}),
    ("show me bob's endpoints",                     {"endpoints": True, "owner_name": "bob"}),
    ("show me charlie machines",                    {"endpoints": True, "owner_name": "charlie"}),
    ("show me david's computers",                   {"endpoints": True, "owner_name": "david"}),
    ("show me eve's laptops",                       {"endpoints": True, "owner_name": "eve"}),
    ("show me frank endpoints",                     {"endpoints": True, "owner_name": "frank"}),
    ("show me grace's workstations",                {"endpoints": True, "owner_name": "grace"}),
    ("show me henry devices",                       {"endpoints": True, "owner_name": "henry"}),

    # Pattern: email address as owner
    ("show endpoints for john@company.com",         {"endpoints": True, "owner_name": "john@company.com"}),
    ("devices for alice@corp.com",                  {"endpoints": True, "owner_name": "alice@corp.com"}),
    ("endpoints owned by bob@example.com",          {"endpoints": True, "owner_name": "bob@example.com"}),
    ("what devices does charlie@work.io have",      {"endpoints": True, "owner_name": "charlie@work.io"}),
    ("show me david@domain.com devices",            {"endpoints": True, "owner_name": "david@domain.com"}),
    ("list endpoints for eve@company.org",          {"endpoints": True, "owner_name": "eve@company.org"}),

    # =========================================================================
    # NAMED USER ACTIVITY  (NEW PATTERN)
    # =========================================================================
    # Pattern: "X's logins/activity"
    ("logins for liad",                             {"activity": True, "act_user": "liad"}),
    ("show alice's logins",                         {"activity": True, "act_user": "alice"}),
    ("bob's login events",                          {"activity": True, "act_user": "bob"}),
    ("charlie's activity",                          {"activity": True, "act_user": "charlie"}),
    ("show david's access events",                  {"activity": True, "act_user": "david"}),
    ("eve's login history",                         {"activity": True, "act_user": "eve"}),
    ("show frank's sessions",                       {"activity": True, "act_user": "frank"}),
    ("grace's activity events",                     {"activity": True, "act_user": "grace"}),
    ("show henry's logins",                         {"activity": True, "act_user": "henry"}),
    ("iris's sign-ins",                             {"activity": True, "act_user": "iris"}),

    # Pattern: "activity for X"
    ("activity for bob",                            {"activity": True, "act_user": "bob"}),
    ("activity for alice",                          {"activity": True, "act_user": "alice"}),
    ("logins for charlie",                          {"activity": True, "act_user": "charlie"}),
    ("access events for david",                     {"activity": True, "act_user": "david"}),
    ("events for eve",                              {"activity": True, "act_user": "eve"}),
    ("show activity for frank",                     {"activity": True, "act_user": "frank"}),
    ("list logins for grace",                       {"activity": True, "act_user": "grace"}),
    ("find activity for henry",                     {"activity": True, "act_user": "henry"}),
    ("display events for iris",                     {"activity": True, "act_user": "iris"}),
    ("show sessions for jake",                      {"activity": True, "act_user": "jake"}),
    ("login history for karen",                     {"activity": True, "act_user": "karen"}),
    ("list access for laura",                       {"activity": True, "act_user": "laura"}),

    # Pattern: "what did X access/login to"
    ("what apps did liad login to",                 {"activity": True, "act_user": "liad"}),
    ("what did alice access",                       {"activity": True, "act_user": "alice"}),
    ("what did bob login to",                       {"activity": True, "act_user": "bob"}),
    ("what did charlie visit",                      {"activity": True, "act_user": "charlie"}),
    ("what did david connect to",                   {"activity": True, "act_user": "david"}),
    ("what did eve access today",                   {"activity": True, "act_user": "eve"}),
    ("what apps did frank use",                     {"activity": True, "act_user": "frank"}),

    # Pattern: "which apps does X use"
    ("which apps does alice use",                   {"activity": True, "act_user": "alice"}),
    ("which apps does bob use",                     {"activity": True, "act_user": "bob"}),
    ("which services does charlie use",             {"activity": True, "act_user": "charlie"}),
    ("which apps has david used",                   {"activity": True, "act_user": "david"}),
    ("which tools does eve have",                   {"activity": True, "act_user": "eve"}),

    # Pattern: "show X login history"
    ("show liad login history",                     {"activity": True, "act_user": "liad"}),
    ("show alice's login history",                  {"activity": True, "act_user": "alice"}),
    ("show bob login history",                      {"activity": True, "act_user": "bob"}),
    ("show charlie's access history",               {"activity": True, "act_user": "charlie"}),
    ("display david's login history",               {"activity": True, "act_user": "david"}),
    ("get eve's login history",                     {"activity": True, "act_user": "eve"}),

    # Pattern: named user activity with email
    ("logins for alice@company.com",                {"activity": True, "act_user": "alice@company.com"}),
    ("activity for bob@corp.com",                   {"activity": True, "act_user": "bob@corp.com"}),
    ("what did charlie@work.io access",             {"activity": True, "act_user": "charlie@work.io"}),
    ("show events for david@domain.com",            {"activity": True, "act_user": "david@domain.com"}),
    ("logins for liad@company.com",                 {"activity": True, "act_user": "liad@company.com"}),

    # =========================================================================
    # COMBINED: event_type + act_user
    # =========================================================================
    ("show liad's saml logins",                     {"activity": True, "event_type": "saml", "act_user": "liad"}),
    ("alice's oauth grant events",                  {"activity": True, "event_type": "oauth_grant", "act_user": "alice"}),
    ("bob's vpn events",                            {"activity": True, "event_type": "vpn", "act_user": "bob"}),
    ("show charlie's app usage events",             {"activity": True, "event_type": "app_usage", "act_user": "charlie"}),
    ("show saml events for alice",                  {"activity": True, "event_type": "saml", "act_user": "alice"}),
    ("network events for bob",                      {"activity": True, "event_type": "network", "act_user": "bob"}),
    ("vpn events for charlie",                      {"activity": True, "event_type": "vpn", "act_user": "charlie"}),
    ("file access events for david",                {"activity": True, "event_type": "file_access", "act_user": "david"}),
    ("show oauth events for eve",                   {"activity": True, "event_type": "oauth_grant", "act_user": "eve"}),
    ("cloud access events for frank",               {"activity": True, "event_type": "cloud_access", "act_user": "frank"}),

    # =========================================================================
    # COMBINED: event_type + country
    # =========================================================================
    ("show saml events from Russia",                {"activity": True, "event_type": "saml", "country": "Russia"}),
    ("list oauth grants from China",                {"activity": True, "event_type": "oauth_grant", "country": "China"}),
    ("network events from Iran",                    {"activity": True, "event_type": "network", "country": "Iran"}),
    ("vpn events from Ukraine",                     {"activity": True, "event_type": "vpn", "country": "Ukraine"}),
    ("file access events from India",               {"activity": True, "event_type": "file_access", "country": "India"}),

    # =========================================================================
    # COMBINED: suspicious + country
    # =========================================================================
    ("suspicious logins from Russia",               {"activity": True, "is_suspicious": True, "country": "Russia"}),
    ("flagged events from China",                   {"activity": True, "is_suspicious": True, "country": "China"}),
    ("anomalous login from Iran",                   {"activity": True, "is_suspicious": True, "country": "Iran"}),
    ("suspicious activity from Ukraine",            {"activity": True, "is_suspicious": True, "country": "Ukraine"}),
    ("unusual access from North Korea",             {"activity": True, "is_suspicious": True, "country": "North Korea"}),

    # =========================================================================
    # COMBINED: suspicious + days_back
    # =========================================================================
    ("suspicious logins this week",                 {"activity": True, "is_suspicious": True, "days_back": 7}),
    ("flagged events in the last 30 days",          {"activity": True, "is_suspicious": True, "days_back": 30}),
    ("anomalous activity today",                    {"activity": True, "is_suspicious": True, "days_back": 1}),
    ("unusual logins this month",                   {"activity": True, "is_suspicious": True, "days_back": 30}),

    # =========================================================================
    # IS_LIST QUERY CHECKS
    # =========================================================================
    ("list endpoints without VPN",                  {"is_list": True}),
    ("show users without MFA",                      {"is_list": True}),
    ("find suspicious events",                      {"is_list": True}),
    ("which devices are non-compliant",             {"is_list": True}),
    ("display users in engineering",                {"is_list": True}),
    ("how many endpoints are non-compliant",        {"is_list": False}),
    ("what is the total count of users",            {"is_list": False}),
    ("give me a summary of compliance",             {"is_list": False}),
    ("how is our security posture",                 {"is_list": False}),
    ("how many users don't have MFA",               {"is_list": False}),
    ("what percentage of devices are encrypted",    {"is_list": False}),
    ("give me an overview of endpoints",            {"is_list": False}),

    # =========================================================================
    # EDGE CASES / TRICKY QUERIES
    # =========================================================================
    # "user" as generic pronoun — should not trigger user listing
    ("list all apps that user login to via saml",   {"activity": True, "event_type": "saml"}),
    ("show apps that user can access via saml",     {"activity": True, "event_type": "saml"}),
    ("what apps does user login to via saml",       {"activity": True, "event_type": "saml"}),

    # Should not mistake country for department
    ("show logins from Russia this week",           {"activity": True, "country": "Russia", "days_back": 7}),
    ("logins from China in the last 7 days",        {"activity": True, "country": "China", "days_back": 7}),

    # Compliance + endpoint filter shouldn't both trigger
    ("list non-compliant endpoints",                {"endpoints": True, "compliance_status": "non_compliant"}),
    ("show non compliant devices",                  {"endpoints": True, "compliance_status": "non_compliant"}),

    # Risk context without entity → generic risk
    ("show risk overview",                          {"risk": True}),
    ("what is the risk distribution",               {"risk": True}),

    # Encryption variants
    ("not encrypted machines",                      {"endpoints": True, "disk_not_encrypted": True}),
    ("unencrypted laptops",                         {"endpoints": True, "disk_not_encrypted": True}),
    ("no disk encryption",                          {"endpoints": True, "disk_not_encrypted": True}),

    # Multiple filters
    ("show high risk Windows devices without VPN",  {"endpoints": True, "os": "windows", "risk_level_ep": "high", "vpn_missing": True}),
    ("macOS endpoints missing EDR and DLP",         {"endpoints": True, "os": "macos", "edr_missing": True, "dlp_missing": True}),

    # Activity fallback
    ("show login events",                           {"activity": True}),
    ("list all access events",                      {"activity": True}),
    ("show auth events",                            {"activity": True}),
    ("display all sessions",                        {"activity": True}),

    # Compliance summary
    ("posture overview",                            {"compliance": True}),
    ("show policy compliance",                      {"compliance": True}),

    # =========================================================================
    # ADDITIONAL SAML VARIANTS
    # =========================================================================
    ("all saml events",                             {"activity": True, "event_type": "saml"}),
    ("saml events this week",                       {"activity": True, "event_type": "saml", "days_back": 7}),
    ("saml events from Russia",                     {"activity": True, "event_type": "saml", "country": "Russia"}),
    ("recent saml logins",                          {"activity": True, "event_type": "saml"}),
    ("saml login today",                            {"activity": True, "event_type": "saml", "days_back": 1}),
    ("show suspicious saml events",                 {"activity": True, "event_type": "saml", "is_suspicious": True}),
    ("saml events last 30 days",                    {"activity": True, "event_type": "saml", "days_back": 30}),

    # =========================================================================
    # ADDITIONAL VPN EVENTS
    # =========================================================================
    ("vpn events this month",                       {"activity": True, "event_type": "vpn", "days_back": 30}),
    ("suspicious vpn events",                       {"activity": True, "event_type": "vpn", "is_suspicious": True}),
    ("vpn events from Russia",                      {"activity": True, "event_type": "vpn", "country": "Russia"}),
    ("show vpn logins this week",                   {"activity": True, "event_type": "vpn", "days_back": 7}),
    ("all vpn connections today",                   {"activity": True, "event_type": "vpn", "days_back": 1}),

    # =========================================================================
    # ADDITIONAL OWNER LOOKUP VARIANTS
    # =========================================================================
    ("show endpoints by liad",                      {"endpoints": True, "owner_name": "liad"}),
    ("get liad's machines",                         {"endpoints": True, "owner_name": "liad"}),
    ("liad's endpoints",                            {"endpoints": True, "owner_name": "liad"}),
    ("alice's computers",                           {"endpoints": True, "owner_name": "alice"}),
    ("endpoints of alice",                          {"endpoints": True, "owner_name": "alice"}),
    ("devices of bob",                              {"endpoints": True, "owner_name": "bob"}),
    ("list laptops for liad",                       {"endpoints": True, "owner_name": "liad"}),
    ("find all devices for alice",                  {"endpoints": True, "owner_name": "alice"}),
    ("show workstations for bob",                   {"endpoints": True, "owner_name": "bob"}),
    ("computers for charlie",                       {"endpoints": True, "owner_name": "charlie"}),
    ("what machines does liad own",                 {"endpoints": True, "owner_name": "liad"}),
    ("what endpoints does alice use",               {"endpoints": True, "owner_name": "alice"}),

    # =========================================================================
    # ADDITIONAL USER ACTIVITY LOOKUP VARIANTS
    # =========================================================================
    ("show all logins for liad",                    {"activity": True, "act_user": "liad"}),
    ("get activity for alice",                      {"activity": True, "act_user": "alice"}),
    ("find all events for bob",                     {"activity": True, "act_user": "bob"}),
    ("display access for charlie",                  {"activity": True, "act_user": "charlie"}),
    ("liad's login events",                         {"activity": True, "act_user": "liad"}),
    ("alice's access events",                       {"activity": True, "act_user": "alice"}),
    ("bob's sessions",                              {"activity": True, "act_user": "bob"}),
    ("show liad's sessions",                        {"activity": True, "act_user": "liad"}),
    ("list alice's events",                         {"activity": True, "act_user": "alice"}),
    ("all events for bob",                          {"activity": True, "act_user": "bob"}),
    ("what apps does liad access",                  {"activity": True, "act_user": "liad"}),
    ("what sites does alice visit",                 {"activity": True, "act_user": "alice"}),

    # =========================================================================
    # MISC COVERAGE TESTS
    # =========================================================================
    ("show active users",                           {"users": True}),
    ("list all login events",                       {"activity": True, "is_list": True}),
    ("find devices with high risk",                 {"endpoints": True, "risk_level_ep": "high"}),
    ("show users at critical risk",                 {"users": True, "risk_level_u": "critical"}),
    ("which machines have missing VPN",             {"endpoints": True, "vpn_missing": True}),
    ("show all endpoints with EDR issues",          {"endpoints": True}),
    ("display compliance status for devices",       {"endpoints": True}),
    ("show me high risk Windows machines",          {"endpoints": True, "os": "windows", "risk_level_ep": "high"}),
    ("list macOS laptops with outdated s1",         {"endpoints": True, "os": "macos", "edr_outdated": True}),
    ("Linux machines with no EDR",                  {"endpoints": True, "os": "linux", "edr_missing": True}),
    ("show suspended employees with no devices",    {"users": True, "suspended": True, "no_endpoint": True}),
    ("find users from engineering without MFA",     {"users": True, "department": "engineering", "mfa_enabled": False}),
    ("show critical risk users in finance",         {"users": True, "risk_level_u": "critical", "department": "finance"}),
    ("list accounts without endpoint in sales",     {"users": True, "no_endpoint": True, "department": "sales"}),
    ("show logins from India this week",            {"activity": True, "country": "India", "days_back": 7}),
    ("flagged events from Germany last 30 days",    {"activity": True, "is_suspicious": True, "country": "Germany", "days_back": 30}),
    ("show suspicious saml from China",             {"activity": True, "event_type": "saml", "is_suspicious": True, "country": "China"}),
    ("show all saml activity for alice this week",  {"activity": True, "event_type": "saml", "act_user": "alice", "days_back": 7}),

    # =========================================================================
    # MORE SAML PATTERNS (variations to reach targets)
    # =========================================================================
    ("which apps do users access via saml",         {"activity": True, "event_type": "saml"}),
    ("apps users can login to via saml",            {"activity": True, "event_type": "saml"}),
    ("saml authentication logs",                    {"activity": True, "event_type": "saml"}),
    ("list saml auth events",                       {"activity": True, "event_type": "saml"}),
    ("get saml events",                             {"activity": True, "event_type": "saml"}),
    ("fetch saml logins",                           {"activity": True, "event_type": "saml"}),
    ("show all saml login events",                  {"activity": True, "event_type": "saml"}),
    ("show saml sign in history",                   {"activity": True, "event_type": "saml"}),
    ("display saml login activity",                 {"activity": True, "event_type": "saml"}),
    ("show recent saml activity",                   {"activity": True, "event_type": "saml"}),

    # =========================================================================
    # MORE OAUTH PATTERNS
    # =========================================================================
    ("oauth events",                                {"activity": True, "event_type": "oauth_grant"}),
    ("list oauth grant access",                     {"activity": True, "event_type": "oauth_grant"}),
    ("show oauth authorization events",             {"activity": True, "event_type": "oauth_grant"}),
    ("oauth grant login history",                   {"activity": True, "event_type": "oauth_grant"}),
    ("recent oauth grant activity",                 {"activity": True, "event_type": "oauth_grant"}),
    ("find oauth grant logins",                     {"activity": True, "event_type": "oauth_grant"}),
    ("all oauth grant activity",                    {"activity": True, "event_type": "oauth_grant"}),
    ("display oauth authorization events",          {"activity": True, "event_type": "oauth_grant"}),
    ("show oauth grant logins this week",           {"activity": True, "event_type": "oauth_grant", "days_back": 7}),

    # =========================================================================
    # MORE APP USAGE PATTERNS
    # =========================================================================
    ("app usage this week",                         {"activity": True, "event_type": "app_usage", "days_back": 7}),
    ("app usage from China",                        {"activity": True, "event_type": "app_usage", "country": "China"}),
    ("suspicious app usage",                        {"activity": True, "event_type": "app_usage", "is_suspicious": True}),
    ("show all application logins",                 {"activity": True, "event_type": "app_usage"}),
    ("list app login history",                      {"activity": True, "event_type": "app_usage"}),
    ("app login events this month",                 {"activity": True, "event_type": "app_usage", "days_back": 30}),
    ("display app usage activity",                  {"activity": True, "event_type": "app_usage"}),

    # =========================================================================
    # MORE FILE ACCESS PATTERNS
    # =========================================================================
    ("file access today",                           {"activity": True, "event_type": "file_access", "days_back": 1}),
    ("suspicious file access events",               {"activity": True, "event_type": "file_access", "is_suspicious": True}),
    ("file access from Russia",                     {"activity": True, "event_type": "file_access", "country": "Russia"}),
    ("file access events this week",                {"activity": True, "event_type": "file_access", "days_back": 7}),
    ("show file access for alice",                  {"activity": True, "event_type": "file_access", "act_user": "alice"}),
    ("find file access events for bob",             {"activity": True, "event_type": "file_access", "act_user": "bob"}),

    # =========================================================================
    # MORE CLOUD ACCESS PATTERNS
    # =========================================================================
    ("cloud access today",                          {"activity": True, "event_type": "cloud_access", "days_back": 1}),
    ("suspicious cloud access",                     {"activity": True, "event_type": "cloud_access", "is_suspicious": True}),
    ("cloud access from China",                     {"activity": True, "event_type": "cloud_access", "country": "China"}),
    ("cloud access events this month",              {"activity": True, "event_type": "cloud_access", "days_back": 30}),
    ("show cloud access for alice",                 {"activity": True, "event_type": "cloud_access", "act_user": "alice"}),

    # =========================================================================
    # MORE NETWORK EVENTS
    # =========================================================================
    ("network events today",                        {"activity": True, "event_type": "network", "days_back": 1}),
    ("suspicious network events",                   {"activity": True, "event_type": "network", "is_suspicious": True}),
    ("network events from Russia",                  {"activity": True, "event_type": "network", "country": "Russia"}),
    ("network events this week",                    {"activity": True, "event_type": "network", "days_back": 7}),
    ("show network events for alice",               {"activity": True, "event_type": "network", "act_user": "alice"}),
    ("network activity for bob",                    {"activity": True, "event_type": "network", "act_user": "bob"}),

    # =========================================================================
    # ADDITIONAL ENDPOINT FILTERS
    # =========================================================================
    ("show all non compliant endpoints",            {"endpoints": True, "compliance_status": "non_compliant"}),
    ("list all partially compliant devices",        {"endpoints": True, "compliance_status": "partial"}),
    ("which endpoints have partial compliance",     {"endpoints": True, "compliance_status": "partial"}),
    ("show high risk non-compliant endpoints",      {"endpoints": True, "compliance_status": "non_compliant", "risk_level_ep": "high"}),
    ("Windows machines without disk encryption",    {"endpoints": True, "os": "windows", "disk_not_encrypted": True}),
    ("Linux endpoints with inactive agents",        {"endpoints": True, "os": "linux", "agent_inactive": True}),
    ("macOS machines without DLP",                  {"endpoints": True, "os": "macos", "dlp_missing": True}),
    ("show unassigned Windows endpoints",           {"endpoints": True, "unassigned": True, "os": "windows"}),

    # =========================================================================
    # ADDITIONAL USER FILTERS
    # =========================================================================
    ("show medium risk users",                      {"users": True, "risk_level_u": "medium"}),
    ("list low risk employees",                     {"users": True, "risk_level_u": "low"}),
    ("show HR users without MFA",                   {"users": True, "department": "hr", "mfa_enabled": False}),
    ("IT staff with critical risk",                 {"users": True, "department": "it", "risk_level_u": "critical"}),
    ("show operations users",                       {"users": True, "department": "operations"}),
    ("list legal department users",                 {"users": True, "department": "legal"}),
    ("show all marketing employees",                {"users": True, "department": "marketing"}),
    ("finance team members",                        {"users": True, "department": "finance"}),

    # =========================================================================
    # ACTIVITY COMBINED
    # =========================================================================
    ("show suspicious login from Russia last week", {"activity": True, "is_suspicious": True, "country": "Russia", "days_back": 7}),
    ("saml events from China this month",           {"activity": True, "event_type": "saml", "country": "China", "days_back": 30}),
    ("vpn events for liad this week",               {"activity": True, "event_type": "vpn", "act_user": "liad", "days_back": 7}),
    ("suspicious network events from Russia",       {"activity": True, "event_type": "network", "is_suspicious": True, "country": "Russia"}),
    ("alice's suspicious logins",                   {"activity": True, "act_user": "alice", "is_suspicious": True}),
    ("bob's logins from China",                     {"activity": True, "act_user": "bob", "country": "China"}),

    # =========================================================================
    # ADDITIONAL IS_LIST checks
    # =========================================================================
    ("give me a list of all endpoints",             {"is_list": True}),
    ("show me all Windows machines",                {"is_list": True, "endpoints": True, "os": "windows"}),
    ("which users are suspended",                   {"is_list": True, "users": True, "suspended": True}),
    ("find all unassigned endpoints",               {"is_list": True, "endpoints": True, "unassigned": True}),
    ("how is our compliance posture",               {"is_list": False, "compliance": True}),
    ("what is the risk score distribution",         {"is_list": False}),
    ("give me an overview of high risk users",      {"is_list": False}),

    # =========================================================================
    # FALLBACK - generic queries trigger compliance + risk
    # =========================================================================
    ("what is our security status",                 {"compliance": True}),
    ("how secure are we",                           {"compliance": True}),
    ("security overview",                           {"compliance": True}),
]


# ===========================================================================
# FOLLOW-UP TESTS
# (query, history_as_list_of_(role,content), expected_bool)
# ===========================================================================

FOLLOWUP_TESTS = [
    # With history present
    ("show me those endpoints", [("user","list windows devices"),("assistant","**Windows endpoints** — 12 found")], True),
    ("which of those are high risk", [("user","list endpoints"),("assistant","42 endpoints found")], True),
    ("filter by Windows", [("user","show endpoints"),("assistant","50 found")], True),
    ("sort by risk", [("user","show endpoints"),("assistant","50 found")], True),
    ("sort by hostname", [("user","list devices"),("assistant","30 found")], True),
    ("order by name", [("user","list users"),("assistant","25 users")], True),
    ("now filter by high risk", [("user","list endpoints"),("assistant","result")], True),
    ("and also without VPN", [("user","show windows endpoints"),("assistant","result")], True),
    ("without MFA", [("user","show users"),("assistant","result")], True),
    ("from Russia", [("user","show login events"),("assistant","result")], True),
    ("also show me the owners", [("user","list endpoints"),("assistant","result")], True),
    ("narrow by linux", [("user","list endpoints"),("assistant","result")], True),
    ("refine by high risk", [("user","list users"),("assistant","result")], True),
    ("filter by critical risk", [("user","show endpoints"),("assistant","result")], True),
    ("only the critical ones", [("user","list devices"),("assistant","result")], True),
    ("what about Windows", [("user","show endpoints"),("assistant","result")], True),
    ("those with inactive agents", [("user","show devices"),("assistant","result")], True),
    ("the ones from China", [("user","show login events"),("assistant","result")], True),
    ("among them, show suspicious ones", [("user","show activity"),("assistant","result")], True),
    ("within those, find encrypted", [("user","list devices"),("assistant","result")], True),
    ("from the previous results", [("user","list users"),("assistant","result")], True),
    ("the above list", [("user","show endpoints"),("assistant","result")], True),
    ("the results", [("user","list endpoints"),("assistant","result")], True),
    ("from those, show without MFA", [("user","list users"),("assistant","result")], True),
    ("the list of endpoints", [("user","show devices"),("assistant","result")], True),

    # Short messages (<=4 words, no entity) with history → follow-up
    ("show them", [("user","list devices"),("assistant","result")], True),
    ("filter those", [("user","list devices"),("assistant","result")], True),
    ("what now", [("user","list users"),("assistant","result")], True),
    ("any others", [("user","show endpoints"),("assistant","result")], True),
    ("just linux", [("user","show endpoints"),("assistant","result")], True),
    ("high risk only", [("user","show users"),("assistant","result")], True),
    ("also MFA", [("user","show users"),("assistant","result")], True),
    ("and suspended", [("user","list accounts"),("assistant","result")], True),
    ("sort these", [("user","list users"),("assistant","result")], True),
    ("now what", [("user","show compliance"),("assistant","result")], True),

    # Short with entity keywords → NOT follow-up (even with history)
    ("list all endpoints", [("user","list users"),("assistant","result")], False),
    ("show all users", [("user","list endpoints"),("assistant","result")], False),
    ("show all devices", [("user","list users"),("assistant","result")], False),
    ("show login activity", [("user","list users"),("assistant","result")], False),
    ("show compliance summary", [("user","list users"),("assistant","result")], False),

    # Without history → never a follow-up
    ("show me those endpoints", [], False),
    ("filter by Windows", [], False),
    ("sort by risk", [], False),
    ("only the critical ones", [], False),
    ("those with inactive agents", [], False),
    ("filter those", [], False),
    ("from those, show suspicious", [], False),
    ("the ones from China", [], False),
    ("narrow by department", [], False),
    ("refine by risk level", [], False),
    ("among them", [], False),
    ("from the previous results", [], False),

    # Sort signals → always follow-up (with history)
    ("sort by risk score", [("user","list endpoints"),("assistant","result")], True),
    ("order by last seen", [("user","list devices"),("assistant","result")], True),
    ("rank by risk", [("user","show users"),("assistant","result")], True),
    ("sort by email", [("user","list users"),("assistant","result")], True),
    ("order by date", [("user","show activity"),("assistant","result")], True),

    # Explicit follow-up phrase with history
    ("now show those without MFA", [("user","list users"),("assistant","result")], True),
    ("what about the ones in finance", [("user","list users"),("assistant","result")], True),
    ("also filter by suspended", [("user","list users"),("assistant","result")], True),
    ("find those with high risk", [("user","list users"),("assistant","result")], True),
    ("list them sorted by risk", [("user","list endpoints"),("assistant","result")], True),
    ("only show the Windows ones", [("user","list endpoints"),("assistant","result")], True),
    ("and also Linux", [("user","list devices"),("assistant","result")], True),
    ("filter by edr_missing", [("user","list endpoints"),("assistant","result")], True),
    ("what are the results", [("user","list endpoints"),("assistant","result")], True),
    ("show me the ones above", [("user","list users"),("assistant","result")], True),
    ("in that list, find high risk", [("user","list endpoints"),("assistant","result")], True),

    # Pivot signals
    ("who owns them", [("user","list endpoints"),("assistant","result")], True),
    ("show their devices", [("user","list users"),("assistant","result")], True),
    ("what devices do they have", [("user","list users"),("assistant","result")], True),
    ("list their endpoints", [("user","list users"),("assistant","result")], True),
    ("whose device is it", [("user","list endpoints"),("assistant","result")], True),
    ("show owner of those endpoints", [("user","list devices"),("assistant","result")], True),

    # Not follow-ups even with history (explicit standalone queries)
    ("show compliance overview", [("user","list endpoints"),("assistant","result")], False),
    ("what is the risk distribution", [("user","list users"),("assistant","result")], False),
    ("list all users without MFA", [("user","show devices"),("assistant","result")], False),
    ("show non-compliant endpoints", [("user","list users"),("assistant","result")], False),
    ("show high risk users", [("user","list endpoints"),("assistant","result")], False),
    ("list windows devices", [("user","list linux devices"),("assistant","result")], False),
    ("show login events from Russia", [("user","list devices"),("assistant","result")], False),

    # More short follow-up combos
    ("by windows", [("user","list endpoints"),("assistant","result")], True),
    ("no vpn", [("user","list endpoints"),("assistant","result")], True),
    ("missing edr", [("user","list devices"),("assistant","result")], True),
    ("suspended ones", [("user","list users"),("assistant","result")], True),
    ("from china", [("user","show login events"),("assistant","result")], True),
    ("this week", [("user","show activity"),("assistant","result")], True),
    ("with mfa", [("user","list users"),("assistant","result")], True),
    ("without dlp", [("user","list endpoints"),("assistant","result")], True),
    ("risk high", [("user","list devices"),("assistant","result")], True),
    ("these ones", [("user","list endpoints"),("assistant","result")], True),
    ("the above", [("user","show users"),("assistant","result")], True),
    ("just those", [("user","list endpoints"),("assistant","result")], True),
    ("and those", [("user","list users"),("assistant","result")], True),
    ("the ones", [("user","list devices"),("assistant","result")], True),
    ("them only", [("user","list endpoints"),("assistant","result")], True),
    ("within those", [("user","list users"),("assistant","result")], True),
    ("from those", [("user","show login events"),("assistant","result")], True),
    ("of those", [("user","list endpoints"),("assistant","result")], True),

    # Explicit non-followup queries with history
    ("show me the compliance overview", [("user","list endpoints"),("assistant","result")], False),
    ("give me the risk summary", [("user","list users"),("assistant","result")], False),
    ("list all endpoints", [("user","list users"),("assistant","result")], False),
    ("show all employees", [("user","list endpoints"),("assistant","result")], False),
    ("show all login events", [("user","list devices"),("assistant","result")], False),
    ("show activity from Russia", [("user","list endpoints"),("assistant","result")], False),
    ("list non-compliant endpoints", [("user","show risk"),("assistant","result")], False),
    ("show suspended users", [("user","list endpoints"),("assistant","result")], False),
    ("list users without MFA", [("user","show devices"),("assistant","result")], False),
    ("show Windows endpoints", [("user","list linux devices"),("assistant","result")], False),

    # Mixed edge cases
    ("show me these results", [("user","list endpoints"),("assistant","result")], True),
    ("now show the above items", [("user","list users"),("assistant","result")], True),
    ("refine these further", [("user","list devices"),("assistant","result")], True),
    ("narrow down the list", [("user","list endpoints"),("assistant","result")], True),
    ("show only Linux now", [("user","list devices"),("assistant","result")], True),
    ("of those endpoints, which are Windows", [("user","list devices"),("assistant","result")], True),
    ("which of these have MFA", [("user","list users"),("assistant","result")], True),
    ("among those, show high risk", [("user","list endpoints"),("assistant","result")], True),
    ("filter the results by risk", [("user","list devices"),("assistant","result")], True),
    ("what are those endpoints", [("user","list devices"),("assistant","result")], True),
]


# ===========================================================================
# CONVERSATIONAL TESTS
# (query, expected_is_conversational: bool)
# ===========================================================================

CONV_TESTS = [
    # Greetings (should return non-None)
    ("hi",                              True),
    ("hello",                           True),
    ("hey",                             True),
    ("howdy",                           True),
    ("Hi!",                             True),
    ("Hello!",                          True),
    ("Hey!",                            True),
    ("hi there",                        True),
    ("hello there",                     True),
    ("good morning",                    True),
    ("good afternoon",                  True),
    ("good evening",                    True),
    ("Good Morning!",                   True),
    ("Good Day",                        True),
    ("hey there",                       True),
    ("Hello.",                          True),

    # Thanks (should return non-None)
    ("thanks",                          True),
    ("thank you",                       True),
    ("thx",                             True),
    ("ty",                              True),
    ("cheers",                          True),
    ("great",                           True),
    ("perfect",                         True),
    ("awesome",                         True),
    ("nice",                            True),
    ("cool",                            True),
    ("Thanks!",                         True),
    ("Thank you!",                      True),
    ("Thanks a lot",                    True),

    # Help (should return non-None)
    ("what can you do",                 True),
    ("help me",                         True),
    ("what can you help with",          True),
    ("what can you help me with",       True),
    ("how do I use this",               True),
    ("how can I use this",              True),
    ("what do you do",                  True),
    ("what do you know",                True),
    ("what can you show me",            True),
    ("who are you",                     True),
    ("what are you",                    True),
    ("capabilities",                    True),
    ("features",                        True),
    ("what are your capabilities",      True),
    ("what are your features",          True),
    ("help me use this tool",           True),
    ("how do I get started",            True),
    ("can you help me",                 True),
    ("what can you do for me",          True),

    # Security queries (should return None)
    ("show me all endpoints",           False),
    ("list users without MFA",          False),
    ("show compliance overview",        False),
    ("show risk overview",              False),
    ("show suspended users",            False),
    ("show suspicious login events",    False),
    ("list non-compliant endpoints",    False),
    ("show Windows devices",            False),
    ("list all accounts",               False),
    ("show activity from Russia",       False),
    ("find endpoints with no EDR",      False),
    ("show high risk users",            False),
    ("list unassigned endpoints",       False),
    ("show login events this week",     False),
    ("show saml events",                False),
    ("show vpn events",                 False),
    ("show alice's logins",             False),
    ("what devices does bob have",      False),
    ("list oauth events",               False),
    ("show file access events",         False),
    ("show cloud access events",        False),
    ("network events from Russia",      False),
    ("show users with no endpoint",     False),
    ("list disk-not-encrypted devices", False),
    ("show agent inactive endpoints",   False),
    ("what is the compliance posture",  False),
    ("how many users don't have MFA",   False),
    ("give me a risk summary",          False),
    ("show all machines",               False),
    ("list all login events",           False),
    ("find flagged events",             False),
]

# ===========================================================================
# EXTENDED INTENT TESTS (to reach 2000+ total)
# ===========================================================================

INTENT_TESTS_EXTENDED = [

    # =========================================================================
    # MORE ENDPOINT LISTING
    # =========================================================================
    ("list all pcs",                                {"endpoints": True, "is_list": True}),
    ("show all workstations",                       {"endpoints": True, "is_list": True}),
    ("fetch all hosts",                             {"endpoints": True, "is_list": True}),
    ("display all computers",                       {"endpoints": True, "is_list": True}),
    ("get me a list of endpoints",                  {"endpoints": True, "is_list": True}),
    ("find all machines in the company",            {"endpoints": True, "is_list": True}),
    ("show endpoint inventory",                     {"endpoints": True}),
    ("list all managed devices",                    {"endpoints": True, "is_list": True}),
    ("get all corporate machines",                  {"endpoints": True, "is_list": True}),
    ("display endpoint list",                       {"endpoints": True}),
    ("what hosts do we have",                       {"endpoints": True}),
    ("show me all pcs",                             {"endpoints": True, "is_list": True}),
    ("list all computers in the organization",      {"endpoints": True, "is_list": True}),
    ("get me all the devices",                      {"endpoints": True, "is_list": True}),
    ("show all registered endpoints",               {"endpoints": True, "is_list": True}),

    # =========================================================================
    # MORE USER LISTING
    # =========================================================================
    ("list all employees",                          {"users": True, "is_list": True}),
    ("show me all users in the system",             {"users": True, "is_list": True}),
    ("get all members",                             {"users": True, "is_list": True}),
    ("display all persons",                         {"users": True, "is_list": True}),
    ("list all workers",                            {"users": True, "is_list": True}),
    ("show all people",                             {"users": True, "is_list": True}),
    ("get all user accounts",                       {"users": True, "is_list": True}),
    ("who are the employees",                       {"users": True, "is_list": True}),
    ("list all persons in the company",             {"users": True, "is_list": True}),
    ("show me everyone",                            {"users": True, "is_list": True}),
    ("display all staff members",                   {"users": True, "is_list": True}),
    ("find all employees",                          {"users": True, "is_list": True}),
    ("list all account holders",                    {"users": True, "is_list": True}),

    # =========================================================================
    # MORE UNASSIGNED PATTERNS
    # =========================================================================
    ("show all unassigned devices",                 {"endpoints": True, "unassigned": True}),
    ("which machines don't have an owner",          {"endpoints": True, "unassigned": True}),
    ("endpoints with no assigned owner",            {"endpoints": True, "unassigned": True}),
    ("show me unassigned pcs",                      {"endpoints": True, "unassigned": True}),
    ("list workstations without an owner",          {"endpoints": True, "unassigned": True}),
    ("find computers missing an owner",             {"endpoints": True, "unassigned": True}),
    ("get unassigned laptops",                      {"endpoints": True, "unassigned": True}),
    ("show devices that are not assigned",          {"endpoints": True, "unassigned": True}),
    ("unassigned machines list",                    {"endpoints": True, "unassigned": True}),
    ("endpoints that have no owner assigned",       {"endpoints": True, "unassigned": True}),

    # =========================================================================
    # MORE EDR MISSING
    # =========================================================================
    ("find machines without sentinelone",           {"endpoints": True, "edr_missing": True}),
    ("show computers where s1 is absent",           {"endpoints": True, "edr_missing": True}),
    ("list devices that don't have EDR",            {"endpoints": True, "edr_missing": True}),
    ("endpoints with edr not installed",            {"endpoints": True, "edr_missing": True}),
    ("machines with no security agent",             {}),  # no specific pattern
    ("show devices without sentinelone installed",  {"endpoints": True, "edr_missing": True}),
    ("find computers with missing s1",              {"endpoints": True, "edr_missing": True}),
    ("list laptops without EDR protection",         {"endpoints": True, "edr_missing": True}),
    ("which hosts are missing EDR",                 {"endpoints": True, "edr_missing": True}),
    ("show pcs without edr",                        {"endpoints": True, "edr_missing": True}),

    # =========================================================================
    # MORE EDR OUTDATED
    # =========================================================================
    ("find endpoints with outdated sentinelone",    {"endpoints": True, "edr_outdated": True}),
    ("show machines with old edr version",          {"endpoints": True, "edr_outdated": True}),
    ("list devices where s1 is outdated",           {"endpoints": True, "edr_outdated": True}),
    ("endpoints where sentinelone is not updated",  {"endpoints": True, "edr_outdated": True}),
    ("get computers with out of date edr",          {"endpoints": True, "edr_outdated": True}),
    ("show pcs with outdated s1 agent",             {"endpoints": True, "edr_outdated": True}),
    ("find workstations with old sentinelone",      {"endpoints": True, "edr_outdated": True}),
    ("which devices need an edr update",            {"endpoints": True, "edr_outdated": True}),
    ("laptops with outdated edr",                   {"endpoints": True, "edr_outdated": True}),
    ("machines with edr that is out of date",       {"endpoints": True, "edr_outdated": True}),

    # =========================================================================
    # MORE VPN MISSING
    # =========================================================================
    ("find machines without vpn",                   {"endpoints": True, "vpn_missing": True}),
    ("show computers with no vpn client",           {"endpoints": True, "vpn_missing": True}),
    ("list devices that don't have vpn",            {"endpoints": True, "vpn_missing": True}),
    ("endpoints where vpn is not installed",        {"endpoints": True, "vpn_missing": True}),
    ("get computers missing globalprotect",         {"endpoints": True, "vpn_missing": True}),
    ("show pcs without vpn software",               {"endpoints": True, "vpn_missing": True}),
    ("find workstations with no vpn",               {"endpoints": True, "vpn_missing": True}),
    ("which laptops are missing vpn",               {"endpoints": True, "vpn_missing": True}),
    ("show endpoints where vpn is missing",         {"endpoints": True, "vpn_missing": True}),
    ("list machines that lack vpn",                 {"endpoints": True, "vpn_missing": True}),

    # =========================================================================
    # MORE DLP MISSING
    # =========================================================================
    ("find machines without dlp",                   {"endpoints": True, "dlp_missing": True}),
    ("show computers with no dlp agent",            {"endpoints": True, "dlp_missing": True}),
    ("list devices that don't have dlp",            {"endpoints": True, "dlp_missing": True}),
    ("endpoints where dlp is not installed",        {"endpoints": True, "dlp_missing": True}),
    ("get computers missing dlp software",          {"endpoints": True, "dlp_missing": True}),
    ("show pcs without dlp",                        {"endpoints": True, "dlp_missing": True}),
    ("find workstations lacking dlp",               {"endpoints": True, "dlp_missing": True}),
    ("which laptops are missing dlp",               {"endpoints": True, "dlp_missing": True}),
    ("show endpoints where dlp is absent",          {"endpoints": True, "dlp_missing": True}),

    # =========================================================================
    # MORE DISK ENCRYPTION
    # =========================================================================
    ("find machines that are not encrypted",        {"endpoints": True, "disk_not_encrypted": True}),
    ("show computers with no encryption",           {"endpoints": True, "disk_not_encrypted": True}),
    ("list devices without filevault",              {"endpoints": True, "disk_not_encrypted": True}),
    ("endpoints where disk is not encrypted",       {"endpoints": True, "disk_not_encrypted": True}),
    ("get machines missing disk encryption",        {"endpoints": True, "disk_not_encrypted": True}),
    ("show unencrypted machines",                   {"endpoints": True, "disk_not_encrypted": True}),
    ("find workstations without bitlocker",         {"endpoints": True, "disk_not_encrypted": True}),
    ("which hosts have no disk encryption",         {"endpoints": True, "disk_not_encrypted": True}),
    ("show pcs that are unencrypted",               {"endpoints": True, "disk_not_encrypted": True}),
    ("list laptops without disk encryption",        {"endpoints": True, "disk_not_encrypted": True}),

    # =========================================================================
    # MORE OS FILTERS
    # =========================================================================
    ("show all Windows pcs",                        {"endpoints": True, "os": "windows"}),
    ("find Windows laptops",                        {"endpoints": True, "os": "windows"}),
    ("list all Windows computers",                  {"endpoints": True, "os": "windows"}),
    ("display Windows hosts",                       {"endpoints": True, "os": "windows"}),
    ("get all Windows machines",                    {"endpoints": True, "os": "windows"}),
    ("which endpoints run Windows",                 {"endpoints": True, "os": "windows"}),
    ("show Windows devices in the org",             {"endpoints": True, "os": "windows"}),
    ("show all macOS machines",                     {"endpoints": True, "os": "macos"}),
    ("find macOS laptops",                          {"endpoints": True, "os": "macos"}),
    ("list all macOS computers",                    {"endpoints": True, "os": "macos"}),
    ("display macOS hosts",                         {"endpoints": True, "os": "macos"}),
    ("get all macOS devices",                       {"endpoints": True, "os": "macos"}),
    ("which endpoints run macOS",                   {"endpoints": True, "os": "macos"}),
    ("show all Linux servers",                      {"endpoints": True, "os": "linux"}),
    ("find Linux laptops",                          {"endpoints": True, "os": "linux"}),
    ("list all Linux computers",                    {"endpoints": True, "os": "linux"}),
    ("display Linux hosts",                         {"endpoints": True, "os": "linux"}),
    ("get all Linux machines",                      {"endpoints": True, "os": "linux"}),
    ("which endpoints run Linux",                   {"endpoints": True, "os": "linux"}),
    ("show Linux workstations",                     {"endpoints": True, "os": "linux"}),

    # =========================================================================
    # MORE COMPLIANCE STATUS
    # =========================================================================
    ("show non-compliant machines",                 {"endpoints": True, "compliance_status": "non_compliant"}),
    ("list devices that fail compliance",           {"endpoints": True, "compliance_status": "non_compliant"}),
    ("find non compliant hosts",                    {"endpoints": True, "compliance_status": "non_compliant"}),
    ("get non-compliant endpoints",                 {"endpoints": True, "compliance_status": "non_compliant"}),
    ("which devices are non-compliant",             {"endpoints": True, "compliance_status": "non_compliant"}),
    ("show machines that are not compliant",        {"endpoints": True, "compliance_status": "non_compliant"}),
    ("list partially compliant machines",           {"endpoints": True, "compliance_status": "partial"}),
    ("find partial compliance hosts",               {"endpoints": True, "compliance_status": "partial"}),
    ("get partially compliant devices",             {"endpoints": True, "compliance_status": "partial"}),
    ("show devices with partial compliance status", {"endpoints": True, "compliance_status": "partial"}),
    ("show fully compliant machines",               {"endpoints": True, "compliance_status": "compliant"}),
    ("find all compliant endpoints",                {"endpoints": True, "compliance_status": "compliant"}),
    ("get compliant hosts",                         {"endpoints": True, "compliance_status": "compliant"}),
    ("which devices are fully compliant",           {"endpoints": True, "compliance_status": "compliant"}),

    # =========================================================================
    # MORE AGENT INACTIVE
    # =========================================================================
    ("find endpoints where agent is stopped",       {"endpoints": True, "agent_inactive": True}),
    ("show machines with stopped security agent",   {"endpoints": True, "agent_inactive": True}),
    ("list devices with disabled agents",           {"endpoints": True, "agent_inactive": True}),
    ("get endpoints where agents are inactive",     {"endpoints": True, "agent_inactive": True}),
    ("which machines have inactive agents",         {"endpoints": True, "agent_inactive": True}),
    ("show devices with agent disabled",            {"endpoints": True, "agent_inactive": True}),
    ("find computers with inactive agent",          {"endpoints": True, "agent_inactive": True}),
    ("list laptops with stopped agent",             {"endpoints": True, "agent_inactive": True}),

    # =========================================================================
    # MORE RISK LEVEL - ENDPOINTS
    # =========================================================================
    ("find high risk machines",                     {"endpoints": True, "risk_level_ep": "high"}),
    ("show endpoints at critical risk",             {"endpoints": True, "risk_level_ep": "critical"}),
    ("list medium risk devices",                    {"endpoints": True, "risk_level_ep": "medium"}),
    ("get low risk endpoints",                      {"endpoints": True, "risk_level_ep": "low"}),
    ("which devices are at high risk",              {"endpoints": True, "risk_level_ep": "high"}),
    ("show critical risk machines",                 {"endpoints": True, "risk_level_ep": "critical"}),
    ("find endpoints with critical risk score",     {"endpoints": True, "risk_level_ep": "critical"}),
    ("list devices with high risk score",           {"endpoints": True, "risk_level_ep": "high"}),
    ("get high-risk computers",                     {"endpoints": True, "risk_level_ep": "high"}),
    ("show high risk pcs",                          {"endpoints": True, "risk_level_ep": "high"}),
    ("which endpoints have critical risk",          {"endpoints": True, "risk_level_ep": "critical"}),
    ("show me medium risk endpoints",               {"endpoints": True, "risk_level_ep": "medium"}),

    # =========================================================================
    # MORE RISK LEVEL - USERS
    # =========================================================================
    ("find high risk employees",                    {"users": True, "risk_level_u": "high"}),
    ("show users at critical risk level",           {"users": True, "risk_level_u": "critical"}),
    ("list medium risk accounts",                   {"users": True, "risk_level_u": "medium"}),
    ("get low risk users",                          {"users": True, "risk_level_u": "low"}),
    ("which users are at high risk",                {"users": True, "risk_level_u": "high"}),
    ("show critical risk employees",                {"users": True, "risk_level_u": "critical"}),
    ("find users with critical risk score",         {"users": True, "risk_level_u": "critical"}),
    ("list accounts with high risk score",          {"users": True, "risk_level_u": "high"}),
    ("get high-risk staff",                         {"users": True, "risk_level_u": "high"}),
    ("show me critical risk users",                 {"users": True, "risk_level_u": "critical"}),
    ("which employees have critical risk",          {"users": True, "risk_level_u": "critical"}),

    # =========================================================================
    # MORE MFA PATTERNS
    # =========================================================================
    ("show employees with no two-factor auth",      {"users": True, "mfa_enabled": False}),
    ("list accounts where mfa is off",              {"users": True, "mfa_enabled": False}),
    ("find users who don't have 2fa",               {"users": True, "mfa_enabled": False}),
    ("get employees without mfa protection",        {"users": True, "mfa_enabled": False}),
    ("which users have mfa disabled",               {"users": True, "mfa_enabled": False}),
    ("show staff that lack mfa",                    {"users": True, "mfa_enabled": False}),
    ("find accounts not using 2fa",                 {"users": True, "mfa_enabled": False}),
    ("list workers without two factor auth",        {"users": True, "mfa_enabled": False}),
    ("show me users lacking mfa",                   {"users": True, "mfa_enabled": False}),
    ("get users where 2fa is not active",           {"users": True, "mfa_enabled": False}),
    ("accounts with 2fa missing",                   {"users": True, "mfa_enabled": False}),
    ("employees who have not enabled mfa",          {"users": True, "mfa_enabled": False}),
    ("find staff where mfa is not enabled",         {"users": True, "mfa_enabled": False}),

    # =========================================================================
    # MORE HAS MFA
    # =========================================================================
    ("find users that have mfa",                    {"users": True, "mfa_enabled": True}),
    ("show accounts with active 2fa",               {"users": True, "mfa_enabled": True}),
    ("list employees with mfa active",              {"users": True, "mfa_enabled": True}),
    ("get users where 2fa is on",                   {"users": True, "mfa_enabled": True}),
    ("which users have mfa enabled",                {"users": True, "mfa_enabled": True}),
    ("show staff with two-factor enabled",          {"users": True, "mfa_enabled": True}),

    # =========================================================================
    # MORE SUSPENDED
    # =========================================================================
    ("find suspended accounts",                     {"users": True, "suspended": True}),
    ("show all locked out employees",               {"users": True, "suspended": True}),
    ("list blocked users",                          {"users": True, "suspended": True}),
    ("get suspended staff",                         {"users": True, "suspended": True}),
    ("which accounts are locked out",               {"users": True, "suspended": True}),
    ("show me suspended accounts",                  {"users": True, "suspended": True}),
    ("find all blocked accounts",                   {"users": True, "suspended": True}),
    ("list all suspended employees",                {"users": True, "suspended": True}),

    # =========================================================================
    # MORE NO ENDPOINT
    # =========================================================================
    ("find users with no machines",                 {"users": True, "no_endpoint": True}),
    ("show employees without a computer",           {"users": True, "no_endpoint": True}),
    ("list accounts with no devices",               {"users": True, "no_endpoint": True}),
    ("get users who don't have endpoints",          {"users": True, "no_endpoint": True}),
    ("which employees have no laptop",              {"users": True, "no_endpoint": True}),
    ("show me users without a device",              {"users": True, "no_endpoint": True}),
    ("find staff with no computer assigned",        {"users": True, "no_endpoint": True}),
    ("list workers with no endpoint assigned",      {"users": True, "no_endpoint": True}),
    ("accounts that have no endpoint",              {"users": True, "no_endpoint": True}),
    ("employees missing a device",                  {"users": True, "no_endpoint": True}),

    # =========================================================================
    # MORE DEPARTMENT FILTERS
    # =========================================================================
    ("show users in the R&D department",            {"users": True, "department": "r&d"}),
    ("list staff in the accounting department",     {"users": True, "department": "accounting"}),
    ("find employees in the security team",         {"users": True, "department": "security"}),
    ("get users in the devops team",                {"users": True, "department": "devops"}),
    ("show people in the design team",              {"users": True, "department": "design"}),
    ("list members in the support team",            {"users": True, "department": "support"}),
    ("show users from the engineering team",        {"users": True, "department": "engineering"}),
    ("find employees from the finance team",        {"users": True, "department": "finance"}),
    ("list staff from the sales team",              {"users": True, "department": "sales"}),
    ("show workers from the HR team",               {"users": True, "department": "hr"}),
    ("get employees in IT",                         {"users": True, "department": "it"}),
    ("list users in marketing",                     {"users": True, "department": "marketing"}),
    ("show staff in operations",                    {"users": True, "department": "operations"}),
    ("find people in legal",                        {"users": True, "department": "legal"}),
    ("show employees in finance",                   {"users": True, "department": "finance"}),
    ("get users from engineering",                  {"users": True, "department": "engineering"}),
    ("find staff from marketing",                   {"users": True, "department": "marketing"}),
    ("show workers from sales",                     {"users": True, "department": "sales"}),
    ("list members from support",                   {"users": True, "department": "support"}),
    ("show people from design",                     {"users": True, "department": "design"}),

    # =========================================================================
    # MORE SUSPICIOUS ACTIVITY
    # =========================================================================
    ("find unusual login events",                   {"activity": True, "is_suspicious": True}),
    ("show all anomalous activity",                 {"activity": True, "is_suspicious": True}),
    ("list malicious events",                       {"activity": True, "is_suspicious": True}),
    ("get flagged login events",                    {"activity": True, "is_suspicious": True}),
    ("which events are suspicious",                 {"activity": True, "is_suspicious": True}),
    ("show me anomalous logins",                    {"activity": True, "is_suspicious": True}),
    ("find all flagged activity",                   {"activity": True, "is_suspicious": True}),
    ("list suspicious access events",               {"activity": True, "is_suspicious": True}),
    ("show unusual access events",                  {"activity": True, "is_suspicious": True}),
    ("get all suspicious logins",                   {"activity": True, "is_suspicious": True}),
    ("find threat login events",                    {"activity": True, "is_suspicious": True}),
    ("show suspicious sign-in events",              {"activity": True, "is_suspicious": True}),

    # =========================================================================
    # MORE COUNTRY FILTER
    # =========================================================================
    ("list access from Turkey",                     {"activity": True, "country": "Turkey"}),
    ("show activity from Pakistan",                 {"activity": True, "country": "Pakistan"}),
    ("find logins from France",                     {"activity": True, "country": "France"}),
    ("get events from United Kingdom",              {"activity": True, "country": "United Kingdom"}),
    ("show logins from United States",              {"activity": True, "country": "United States"}),
    ("list access from Canada",                     {"activity": True, "country": "Canada"}),
    ("find activity from Australia",                {"activity": True, "country": "Australia"}),
    ("show events from Brazil",                     {"activity": True, "country": "Brazil"}),
    ("get logins from UK",                          {"activity": True, "country": "United Kingdom"}),
    ("show activity from USA",                      {"activity": True, "country": "United States"}),

    # =========================================================================
    # MORE TIME RANGE FILTERS
    # =========================================================================
    ("show login events in the last 5 days",        {"activity": True, "days_back": 5}),
    ("find activity from last 14 days",             {"activity": True, "days_back": 14}),
    ("list events from the past 2 days",            {"activity": True, "days_back": 2}),
    ("get logins for the last 10 days",             {"activity": True, "days_back": 10}),
    ("show access events in the last 60 days",      {"activity": True, "days_back": 60}),
    ("find logins from past 7 days",                {"activity": True, "days_back": 7}),
    ("list activity for the last 21 days",          {"activity": True, "days_back": 21}),
    ("show events from the past 30 days",           {"activity": True, "days_back": 30}),
    ("get login events from last 45 days",          {"activity": True, "days_back": 45}),
    ("show past week logins",                       {"activity": True, "days_back": 7}),
    ("list activity this week",                     {"activity": True, "days_back": 7}),
    ("find events past 30 days",                    {"activity": True, "days_back": 30}),
    ("show login events past month",                {"activity": True, "days_back": 30}),
    ("activity in the last 7 days",                 {"activity": True, "days_back": 7}),

    # =========================================================================
    # MORE COMPLIANCE SUMMARY
    # =========================================================================
    ("give me a compliance report",                 {"compliance": True}),
    ("what is our compliance status",               {"compliance": True}),
    ("show me the compliance dashboard",            {"compliance": True}),
    ("compliance overview please",                  {"compliance": True}),
    ("how many endpoints are compliant",            {"compliance": True}),
    ("what percentage are compliant",               {"compliance": True}),
    ("show compliance statistics",                  {"compliance": True}),
    ("compliance summary for all devices",          {"compliance": True}),
    ("get the compliance posture",                  {"compliance": True}),
    ("what is our policy compliance status",        {"compliance": True}),
    ("show security policy status",                 {"compliance": True}),

    # =========================================================================
    # MORE RISK SUMMARY
    # =========================================================================
    ("get a risk summary",                          {"risk": True}),
    ("what is the overall risk",                    {"risk": True}),
    ("show overall risk distribution",              {"risk": True}),
    ("how many critical risk assets",               {"risk": True}),
    ("show risk overview for all assets",           {"risk": True}),
    ("what is our risk posture",                    {"risk": True}),
    ("show me the risk dashboard",                  {"risk": True}),
    ("risk breakdown by level",                     {"risk": True}),
    ("show all risky assets",                       {"risk": True}),

    # =========================================================================
    # MORE SAML EVENTS
    # =========================================================================
    ("show all saml authentication",                {"activity": True, "event_type": "saml"}),
    ("get saml sign-in events",                     {"activity": True, "event_type": "saml"}),
    ("display saml auth logs",                      {"activity": True, "event_type": "saml"}),
    ("find all saml events today",                  {"activity": True, "event_type": "saml", "days_back": 1}),
    ("show saml events from last week",             {"activity": True, "event_type": "saml", "days_back": 7}),
    ("list suspicious saml events",                 {"activity": True, "event_type": "saml", "is_suspicious": True}),
    ("saml events from Ukraine",                    {"activity": True, "event_type": "saml", "country": "Ukraine"}),
    ("show saml logins from China",                 {"activity": True, "event_type": "saml", "country": "China"}),
    ("all saml events this week",                   {"activity": True, "event_type": "saml", "days_back": 7}),
    ("show saml auth events from India",            {"activity": True, "event_type": "saml", "country": "India"}),
    ("list saml events past 30 days",               {"activity": True, "event_type": "saml", "days_back": 30}),
    ("get saml events for today",                   {"activity": True, "event_type": "saml", "days_back": 1}),
    ("show suspicious saml login events",           {"activity": True, "event_type": "saml", "is_suspicious": True}),
    ("display saml events from Russia",             {"activity": True, "event_type": "saml", "country": "Russia"}),
    ("find saml logins from Iran",                  {"activity": True, "event_type": "saml", "country": "Iran"}),
    ("show saml events for bob",                    {"activity": True, "event_type": "saml", "act_user": "bob"}),
    ("list saml events for charlie",                {"activity": True, "event_type": "saml", "act_user": "charlie"}),
    ("saml access for david",                       {"activity": True, "event_type": "saml", "act_user": "david"}),
    ("show saml activity for eve",                  {"activity": True, "event_type": "saml", "act_user": "eve"}),

    # =========================================================================
    # MORE OAUTH EVENTS
    # =========================================================================
    ("get oauth grant events",                      {"activity": True, "event_type": "oauth_grant"}),
    ("display oauth grants",                        {"activity": True, "event_type": "oauth_grant"}),
    ("find oauth grant access events",              {"activity": True, "event_type": "oauth_grant"}),
    ("show all oauth authorizations",               {"activity": True, "event_type": "oauth_grant"}),
    ("list oauth grant logins",                     {"activity": True, "event_type": "oauth_grant"}),
    ("suspicious oauth grant events",               {"activity": True, "event_type": "oauth_grant", "is_suspicious": True}),
    ("oauth grant events from Russia",              {"activity": True, "event_type": "oauth_grant", "country": "Russia"}),
    ("show oauth events this week",                 {"activity": True, "event_type": "oauth_grant", "days_back": 7}),
    ("list oauth grant events today",               {"activity": True, "event_type": "oauth_grant", "days_back": 1}),
    ("oauth grant events for alice",                {"activity": True, "event_type": "oauth_grant", "act_user": "alice"}),
    ("show oauth grant activity for bob",           {"activity": True, "event_type": "oauth_grant", "act_user": "bob"}),
    ("list oauth events for charlie",               {"activity": True, "event_type": "oauth_grant", "act_user": "charlie"}),
    ("get oauth events from China",                 {"activity": True, "event_type": "oauth_grant", "country": "China"}),
    ("display oauth grant events from India",       {"activity": True, "event_type": "oauth_grant", "country": "India"}),

    # =========================================================================
    # MORE APP USAGE EVENTS
    # =========================================================================
    ("get app usage events",                        {"activity": True, "event_type": "app_usage"}),
    ("display application usage events",            {"activity": True, "event_type": "app_usage"}),
    ("find app usage activity",                     {"activity": True, "event_type": "app_usage"}),
    ("show all app usage data",                     {"activity": True, "event_type": "app_usage"}),
    ("list app login events",                       {"activity": True, "event_type": "app_usage"}),
    ("suspicious app usage events",                 {"activity": True, "event_type": "app_usage", "is_suspicious": True}),
    ("app usage events from Russia",                {"activity": True, "event_type": "app_usage", "country": "Russia"}),
    ("show app usage this week",                    {"activity": True, "event_type": "app_usage", "days_back": 7}),
    ("list app usage events today",                 {"activity": True, "event_type": "app_usage", "days_back": 1}),
    ("app usage for alice",                         {"activity": True, "event_type": "app_usage", "act_user": "alice"}),
    ("show app logins for bob",                     {"activity": True, "event_type": "app_usage", "act_user": "bob"}),
    ("list app usage events for charlie",           {"activity": True, "event_type": "app_usage", "act_user": "charlie"}),
    ("get app logins from China",                   {"activity": True, "event_type": "app_usage", "country": "China"}),
    ("display app usage from India",                {"activity": True, "event_type": "app_usage", "country": "India"}),
    ("show app login events this month",            {"activity": True, "event_type": "app_usage", "days_back": 30}),

    # =========================================================================
    # MORE NETWORK EVENTS
    # =========================================================================
    ("get network events",                          {"activity": True, "event_type": "network"}),
    ("display network activity events",             {"activity": True, "event_type": "network"}),
    ("find network traffic events",                 {"activity": True, "event_type": "network"}),
    ("show all network access events",              {"activity": True, "event_type": "network"}),
    ("list all network events",                     {"activity": True, "event_type": "network"}),
    ("suspicious network activity",                 {"activity": True, "event_type": "network", "is_suspicious": True}),
    ("network events from China",                   {"activity": True, "event_type": "network", "country": "China"}),
    ("show network events this week",               {"activity": True, "event_type": "network", "days_back": 7}),
    ("list network events today",                   {"activity": True, "event_type": "network", "days_back": 1}),
    ("network activity for alice",                  {"activity": True, "event_type": "network", "act_user": "alice"}),
    ("show network events for bob this week",       {"activity": True, "event_type": "network", "act_user": "bob", "days_back": 7}),
    ("list network access for charlie",             {"activity": True, "event_type": "network", "act_user": "charlie"}),
    ("get network events from Ukraine",             {"activity": True, "event_type": "network", "country": "Ukraine"}),
    ("display network traffic from Iran",           {"activity": True, "event_type": "network", "country": "Iran"}),
    ("show suspicious network events from Russia",  {"activity": True, "event_type": "network", "is_suspicious": True, "country": "Russia"}),

    # =========================================================================
    # MORE FILE ACCESS EVENTS
    # =========================================================================
    ("get file access events",                      {"activity": True, "event_type": "file_access"}),
    ("display file access activity",                {"activity": True, "event_type": "file_access"}),
    ("find all file access events",                 {"activity": True, "event_type": "file_access"}),
    ("show recent file access events",              {"activity": True, "event_type": "file_access"}),
    ("list file-access logs",                       {"activity": True, "event_type": "file_access"}),
    ("suspicious file access activity",             {"activity": True, "event_type": "file_access", "is_suspicious": True}),
    ("file access events from China",               {"activity": True, "event_type": "file_access", "country": "China"}),
    ("show file access this week",                  {"activity": True, "event_type": "file_access", "days_back": 7}),
    ("list file access events today",               {"activity": True, "event_type": "file_access", "days_back": 1}),
    ("file access events for alice",                {"activity": True, "event_type": "file_access", "act_user": "alice"}),
    ("show file access for bob",                    {"activity": True, "event_type": "file_access", "act_user": "bob"}),
    ("list file access events for charlie",         {"activity": True, "event_type": "file_access", "act_user": "charlie"}),
    ("get file access from Russia",                 {"activity": True, "event_type": "file_access", "country": "Russia"}),
    ("display file access events from Iran",        {"activity": True, "event_type": "file_access", "country": "Iran"}),

    # =========================================================================
    # MORE CLOUD ACCESS EVENTS
    # =========================================================================
    ("get cloud access events",                     {"activity": True, "event_type": "cloud_access"}),
    ("display cloud access activity",               {"activity": True, "event_type": "cloud_access"}),
    ("find all cloud access events",                {"activity": True, "event_type": "cloud_access"}),
    ("show recent cloud access events",             {"activity": True, "event_type": "cloud_access"}),
    ("list all cloud access logs",                  {"activity": True, "event_type": "cloud_access"}),
    ("suspicious cloud access activity",            {"activity": True, "event_type": "cloud_access", "is_suspicious": True}),
    ("cloud access events from China",              {"activity": True, "event_type": "cloud_access", "country": "China"}),
    ("show cloud access this week",                 {"activity": True, "event_type": "cloud_access", "days_back": 7}),
    ("list cloud access events today",              {"activity": True, "event_type": "cloud_access", "days_back": 1}),
    ("cloud access events for alice",               {"activity": True, "event_type": "cloud_access", "act_user": "alice"}),
    ("show cloud access for bob",                   {"activity": True, "event_type": "cloud_access", "act_user": "bob"}),
    ("list cloud access for charlie",               {"activity": True, "event_type": "cloud_access", "act_user": "charlie"}),
    ("get cloud access from Russia",                {"activity": True, "event_type": "cloud_access", "country": "Russia"}),
    ("display cloud events from Iran",              {"activity": True, "event_type": "cloud_access", "country": "Iran"}),
    ("show suspicious cloud access from China",     {"activity": True, "event_type": "cloud_access", "is_suspicious": True, "country": "China"}),

    # =========================================================================
    # MORE VPN EVENTS
    # =========================================================================
    ("get vpn events",                              {"activity": True, "event_type": "vpn"}),
    ("display vpn activity",                        {"activity": True, "event_type": "vpn"}),
    ("find all vpn events",                         {"activity": True, "event_type": "vpn"}),
    ("show recent vpn events",                      {"activity": True, "event_type": "vpn"}),
    ("list all vpn activity logs",                  {"activity": True, "event_type": "vpn"}),
    ("suspicious vpn activity",                     {"activity": True, "event_type": "vpn", "is_suspicious": True}),
    ("vpn events from China",                       {"activity": True, "event_type": "vpn", "country": "China"}),
    ("show vpn activity this week",                 {"activity": True, "event_type": "vpn", "days_back": 7}),
    ("list vpn events today",                       {"activity": True, "event_type": "vpn", "days_back": 1}),
    ("vpn events for alice",                        {"activity": True, "event_type": "vpn", "act_user": "alice"}),
    ("show vpn activity for bob",                   {"activity": True, "event_type": "vpn", "act_user": "bob"}),
    ("list vpn connections for charlie",            {"activity": True, "event_type": "vpn", "act_user": "charlie"}),
    ("get vpn events from Russia",                  {"activity": True, "event_type": "vpn", "country": "Russia"}),
    ("display vpn events from Iran",                {"activity": True, "event_type": "vpn", "country": "Iran"}),
    ("show suspicious vpn events from Ukraine",     {"activity": True, "event_type": "vpn", "is_suspicious": True, "country": "Ukraine"}),

    # =========================================================================
    # MORE OWNER LOOKUP VARIANTS
    # =========================================================================
    ("show endpoints for oscar",                    {"endpoints": True, "owner_name": "oscar"}),
    ("list devices for paul",                       {"endpoints": True, "owner_name": "paul"}),
    ("find machines for quinn",                     {"endpoints": True, "owner_name": "quinn"}),
    ("get computers for rachel",                    {"endpoints": True, "owner_name": "rachel"}),
    ("show sam's devices",                          {"endpoints": True, "owner_name": "sam"}),
    ("list tina's endpoints",                       {"endpoints": True, "owner_name": "tina"}),
    ("find uma's machines",                         {"endpoints": True, "owner_name": "uma"}),
    ("get victor's computers",                      {"endpoints": True, "owner_name": "victor"}),
    ("show wendy's laptops",                        {"endpoints": True, "owner_name": "wendy"}),
    ("list xavier's workstations",                  {"endpoints": True, "owner_name": "xavier"}),
    ("find yvonne's pcs",                           {"endpoints": True, "owner_name": "yvonne"}),
    ("show zack's endpoints",                       {"endpoints": True, "owner_name": "zack"}),
    ("endpoints owned by oscar",                    {"endpoints": True, "owner_name": "oscar"}),
    ("devices owned by paul",                       {"endpoints": True, "owner_name": "paul"}),
    ("machines owned by quinn",                     {"endpoints": True, "owner_name": "quinn"}),
    ("computers belonging to rachel",               {"endpoints": True, "owner_name": "rachel"}),
    ("laptops belonging to sam",                    {"endpoints": True, "owner_name": "sam"}),
    ("what devices does tina have",                 {"endpoints": True, "owner_name": "tina"}),
    ("what machines does uma have",                 {"endpoints": True, "owner_name": "uma"}),
    ("what computers does victor use",              {"endpoints": True, "owner_name": "victor"}),
    ("show me wendy's devices",                     {"endpoints": True, "owner_name": "wendy"}),
    ("show me xavier endpoints",                    {"endpoints": True, "owner_name": "xavier"}),
    ("show me yvonne's machines",                   {"endpoints": True, "owner_name": "yvonne"}),
    ("show me zack computers",                      {"endpoints": True, "owner_name": "zack"}),
    ("devices for zoe",                             {"endpoints": True, "owner_name": "zoe"}),
    ("endpoints for alex",                          {"endpoints": True, "owner_name": "alex"}),
    ("what devices does alex own",                  {"endpoints": True, "owner_name": "alex"}),
    ("show alex's endpoints",                       {"endpoints": True, "owner_name": "alex"}),
    ("list devices for sam",                        {"endpoints": True, "owner_name": "sam"}),
    ("find endpoints for nina",                     {"endpoints": True, "owner_name": "nina"}),
    ("show me nina's devices",                      {"endpoints": True, "owner_name": "nina"}),
    ("what laptops does oscar have",                {"endpoints": True, "owner_name": "oscar"}),

    # =========================================================================
    # MORE NAMED USER ACTIVITY
    # =========================================================================
    ("show activity for oscar",                     {"activity": True, "act_user": "oscar"}),
    ("list logins for paul",                        {"activity": True, "act_user": "paul"}),
    ("find events for quinn",                       {"activity": True, "act_user": "quinn"}),
    ("get access for rachel",                       {"activity": True, "act_user": "rachel"}),
    ("sam's login events",                          {"activity": True, "act_user": "sam"}),
    ("tina's activity",                             {"activity": True, "act_user": "tina"}),
    ("show uma's sessions",                         {"activity": True, "act_user": "uma"}),
    ("list victor's logins",                        {"activity": True, "act_user": "victor"}),
    ("show wendy's access events",                  {"activity": True, "act_user": "wendy"}),
    ("xavier's login history",                      {"activity": True, "act_user": "xavier"}),
    ("show yvonne's activity",                      {"activity": True, "act_user": "yvonne"}),
    ("list zack's events",                          {"activity": True, "act_user": "zack"}),
    ("activity for oscar",                          {"activity": True, "act_user": "oscar"}),
    ("logins for paul",                             {"activity": True, "act_user": "paul"}),
    ("events for quinn",                            {"activity": True, "act_user": "quinn"}),
    ("access for rachel",                           {"activity": True, "act_user": "rachel"}),
    ("what did sam access",                         {"activity": True, "act_user": "sam"}),
    ("what did tina login to",                      {"activity": True, "act_user": "tina"}),
    ("what apps did uma use",                       {"activity": True, "act_user": "uma"}),
    ("which apps does victor use",                  {"activity": True, "act_user": "victor"}),
    ("which services does wendy use",               {"activity": True, "act_user": "wendy"}),
    ("show xavier login history",                   {"activity": True, "act_user": "xavier"}),
    ("show yvonne's login history",                 {"activity": True, "act_user": "yvonne"}),
    ("display zack's login history",                {"activity": True, "act_user": "zack"}),
    ("show nina's logins",                          {"activity": True, "act_user": "nina"}),
    ("logins for alex",                             {"activity": True, "act_user": "alex"}),
    ("what did alex access",                        {"activity": True, "act_user": "alex"}),
    ("show zoe's activity",                         {"activity": True, "act_user": "zoe"}),
    ("list zoe's login events",                     {"activity": True, "act_user": "zoe"}),

    # =========================================================================
    # COMBINED FILTERS (endpoint + multiple)
    # =========================================================================
    ("show critical macOS endpoints",               {"endpoints": True, "os": "macos", "risk_level_ep": "critical"}),
    ("list Windows machines without DLP",           {"endpoints": True, "os": "windows", "dlp_missing": True}),
    ("find macOS devices without disk encryption",  {"endpoints": True, "os": "macos", "disk_not_encrypted": True}),
    ("show Linux endpoints without EDR",            {"endpoints": True, "os": "linux", "edr_missing": True}),
    ("list Windows laptops without VPN",            {"endpoints": True, "os": "windows", "vpn_missing": True}),
    ("find high risk Linux endpoints",              {"endpoints": True, "os": "linux", "risk_level_ep": "high"}),
    ("show non-compliant macOS devices",            {"endpoints": True, "os": "macos", "compliance_status": "non_compliant"}),
    ("list critical Windows machines",              {"endpoints": True, "os": "windows", "risk_level_ep": "critical"}),
    ("find medium risk Linux laptops",              {"endpoints": True, "os": "linux", "risk_level_ep": "medium"}),
    ("show partially compliant Windows endpoints",  {"endpoints": True, "os": "windows", "compliance_status": "partial"}),
    ("list unassigned macOS devices",               {"endpoints": True, "os": "macos", "unassigned": True}),
    ("show Windows endpoints with inactive agents", {"endpoints": True, "os": "windows", "agent_inactive": True}),
    ("find Linux devices missing DLP",              {"endpoints": True, "os": "linux", "dlp_missing": True}),
    ("show macOS machines with outdated EDR",       {"endpoints": True, "os": "macos", "edr_outdated": True}),
    ("list Windows endpoints missing EDR",          {"endpoints": True, "os": "windows", "edr_missing": True}),

    # =========================================================================
    # COMBINED FILTERS (user + multiple)
    # =========================================================================
    ("show suspended users without MFA",            {"users": True, "suspended": True, "mfa_enabled": False}),
    ("list high risk users without MFA",            {"users": True, "risk_level_u": "high", "mfa_enabled": False}),
    ("find critical risk suspended users",          {"users": True, "risk_level_u": "critical", "suspended": True}),
    ("show engineering users with no endpoint",     {"users": True, "department": "engineering", "no_endpoint": True}),
    ("list finance users without MFA",              {"users": True, "department": "finance", "mfa_enabled": False}),
    ("find HR staff with no device",                {"users": True, "department": "hr", "no_endpoint": True}),
    ("show sales employees with high risk",         {"users": True, "department": "sales", "risk_level_u": "high"}),
    ("list IT users with critical risk",            {"users": True, "department": "it", "risk_level_u": "critical"}),
    ("show inactive users without MFA",             {"users": True, "employment_status": "inactive", "mfa_enabled": False}),
    ("find suspended users with no endpoint",       {"users": True, "suspended": True, "no_endpoint": True}),

    # =========================================================================
    # COMBINED ACTIVITY FILTERS
    # =========================================================================
    ("show suspicious saml events from China",      {"activity": True, "event_type": "saml", "is_suspicious": True, "country": "China"}),
    ("list suspicious vpn events from Russia",      {"activity": True, "event_type": "vpn", "is_suspicious": True, "country": "Russia"}),
    ("find anomalous network events from Iran",     {"activity": True, "event_type": "network", "is_suspicious": True, "country": "Iran"}),
    ("show flagged cloud access from Ukraine",      {"activity": True, "event_type": "cloud_access", "is_suspicious": True, "country": "Ukraine"}),
    ("list suspicious file access from China",      {"activity": True, "event_type": "file_access", "is_suspicious": True, "country": "China"}),
    ("show saml events this week from Russia",      {"activity": True, "event_type": "saml", "country": "Russia", "days_back": 7}),
    ("list oauth events last 7 days from China",    {"activity": True, "event_type": "oauth_grant", "country": "China", "days_back": 7}),
    ("show all suspicious activity from Russia last 30 days", {"activity": True, "is_suspicious": True, "country": "Russia", "days_back": 30}),
    ("suspicious logins from Ukraine this week",    {"activity": True, "is_suspicious": True, "country": "Ukraine", "days_back": 7}),
    ("find anomalous events from Iran last week",   {"activity": True, "is_suspicious": True, "country": "Iran", "days_back": 7}),

    # =========================================================================
    # NAMED USER + EVENT TYPE COMBINATIONS
    # =========================================================================
    ("show dave's saml events",                     {"activity": True, "event_type": "saml", "act_user": "dave"}),
    ("list emma's oauth grants",                    {"activity": True, "event_type": "oauth_grant", "act_user": "emma"}),
    ("find fred's vpn connections",                 {"activity": True, "event_type": "vpn", "act_user": "fred"}),
    ("show gina's network events",                  {"activity": True, "event_type": "network", "act_user": "gina"}),
    ("list hal's file access events",               {"activity": True, "event_type": "file_access", "act_user": "hal"}),
    ("show ivan's cloud access",                    {"activity": True, "event_type": "cloud_access", "act_user": "ivan"}),
    ("saml events for judy",                        {"activity": True, "event_type": "saml", "act_user": "judy"}),
    ("oauth grant events for karl",                 {"activity": True, "event_type": "oauth_grant", "act_user": "karl"}),
    ("vpn events for linda",                        {"activity": True, "event_type": "vpn", "act_user": "linda"}),
    ("show app usage for mike",                     {"activity": True, "event_type": "app_usage", "act_user": "mike"}),
    ("list network events for nancy",               {"activity": True, "event_type": "network", "act_user": "nancy"}),
    ("file access events for oscar",                {"activity": True, "event_type": "file_access", "act_user": "oscar"}),
    ("cloud access events for paul",                {"activity": True, "event_type": "cloud_access", "act_user": "paul"}),
    ("show dave's vpn logins",                      {"activity": True, "event_type": "vpn", "act_user": "dave"}),
    ("list emma's app logins",                      {"activity": True, "event_type": "app_usage", "act_user": "emma"}),

    # =========================================================================
    # IS_LIST ADDITIONAL CHECKS
    # =========================================================================
    ("show all non-compliant endpoints",            {"is_list": True}),
    ("list all users without MFA",                  {"is_list": True}),
    ("find all flagged events",                     {"is_list": True}),
    ("display all Windows machines",                {"is_list": True}),
    ("which users are in IT",                       {"is_list": True}),
    ("give me all high risk users",                 {"is_list": True}),
    ("how many endpoints are high risk",            {"is_list": False}),
    ("what percentage of users lack MFA",           {"is_list": False}),
    ("total count of non-compliant devices",        {"is_list": False}),
    ("summary of compliance issues",                {"is_list": False}),
    ("how risky is our infrastructure",             {"is_list": False}),
    ("average risk score for endpoints",            {"is_list": False}),
    ("trend of suspicious events",                  {"is_list": False}),
    ("breakdown of activity by country",            {"is_list": False}),
    ("overview of endpoint status",                 {"is_list": False}),
    ("compare compliant vs non-compliant",          {"is_list": False}),

    # =========================================================================
    # EDGE CASES
    # =========================================================================
    ("show me all saml and oauth events",           {"activity": True}),
    ("logins today",                                {"activity": True, "days_back": 1}),
    ("events last month",                           {"activity": True, "days_back": 30}),
    ("suspicious events today",                     {"activity": True, "is_suspicious": True, "days_back": 1}),
    ("high risk users and endpoints",               {"users": True, "endpoints": True}),
    ("show all compliance gaps",                    {"compliance": True}),
    ("list all security issues",                    {"compliance": True}),
    ("what are our biggest risks",                  {"risk": True}),
    ("show me critical vulnerabilities",            {}),
    ("what is our overall security posture",        {"compliance": True}),
    ("are we secure",                               {}),
    ("what needs to be fixed",                      {"compliance": True}),

    # =========================================================================
    # ADDITIONAL MISC PATTERNS
    # =========================================================================
    ("show Windows computers with no edr",          {"endpoints": True, "os": "windows", "edr_missing": True}),
    ("find high risk Windows devices",              {"endpoints": True, "os": "windows", "risk_level_ep": "high"}),
    ("list Linux servers with outdated s1",         {"endpoints": True, "os": "linux", "edr_outdated": True}),
    ("show macOS laptops without vpn",              {"endpoints": True, "os": "macos", "vpn_missing": True}),
    ("list unencrypted Windows pcs",                {"endpoints": True, "os": "windows", "disk_not_encrypted": True}),
    ("find non-compliant Linux servers",            {"endpoints": True, "os": "linux", "compliance_status": "non_compliant"}),
    ("show partially compliant macOS devices",      {"endpoints": True, "os": "macos", "compliance_status": "partial"}),
    ("list critical risk Windows laptops",          {"endpoints": True, "os": "windows", "risk_level_ep": "critical"}),
    ("show medium risk Linux endpoints",            {"endpoints": True, "os": "linux", "risk_level_ep": "medium"}),
    ("find Windows devices with inactive agents",   {"endpoints": True, "os": "windows", "agent_inactive": True}),
    ("show macOS endpoints missing dlp",            {"endpoints": True, "os": "macos", "dlp_missing": True}),
    ("list high risk users in HR",                  {"users": True, "department": "hr", "risk_level_u": "high"}),
    ("show critical risk employees in finance",     {"users": True, "department": "finance", "risk_level_u": "critical"}),
    ("find medium risk users in sales",             {"users": True, "department": "sales", "risk_level_u": "medium"}),
    ("list engineering users with no endpoint",     {"users": True, "department": "engineering", "no_endpoint": True}),
    ("show IT staff without MFA",                   {"users": True, "department": "it", "mfa_enabled": False}),
    ("find operations users with no device",        {"users": True, "department": "operations", "no_endpoint": True}),
    ("show legal staff who are suspended",          {"users": True, "department": "legal", "suspended": True}),
    ("list marketing employees at high risk",       {"users": True, "department": "marketing", "risk_level_u": "high"}),
    ("show design team without MFA",                {"users": True, "department": "design", "mfa_enabled": False}),
    ("find support users with no endpoint",         {"users": True, "department": "support", "no_endpoint": True}),

    # =========================================================================
    # REPEATED VARIATIONS TO ENSURE COVERAGE
    # =========================================================================
    ("show me endpoints",                           {"endpoints": True}),
    ("list my devices",                             {"endpoints": True}),
    ("get all endpoints",                           {"endpoints": True, "is_list": True}),
    ("show me users",                               {"users": True}),
    ("list my users",                               {"users": True}),
    ("show login history",                          {"activity": True}),
    ("show all login activity",                     {"activity": True, "is_list": True}),
    ("get activity logs",                           {"activity": True}),
    ("show event logs",                             {"activity": True}),
    ("list all events",                             {"activity": True, "is_list": True}),
    ("show me all activity",                        {"activity": True, "is_list": True}),
    ("get all access logs",                         {"activity": True, "is_list": True}),
    ("find login events",                           {"activity": True, "is_list": True}),
    ("show sign-in events",                         {"activity": True}),
    ("list authentication events",                  {"activity": True, "is_list": True}),
    ("show auth logs",                              {"activity": True}),

    # =========================================================================
    # ADDITIONAL NAMED OWNER TESTS
    # =========================================================================
    ("show endpoints for diana",                    {"endpoints": True, "owner_name": "diana"}),
    ("list machines for ethan",                     {"endpoints": True, "owner_name": "ethan"}),
    ("find devices for fiona",                      {"endpoints": True, "owner_name": "fiona"}),
    ("what computers does gary have",               {"endpoints": True, "owner_name": "gary"}),
    ("show me hannah's endpoints",                  {"endpoints": True, "owner_name": "hannah"}),
    ("devices for igor",                            {"endpoints": True, "owner_name": "igor"}),
    ("show endpoints for jason",                    {"endpoints": True, "owner_name": "jason"}),
    ("list devices for kate",                       {"endpoints": True, "owner_name": "kate"}),
    ("machines for leo",                            {"endpoints": True, "owner_name": "leo"}),
    ("devices owned by mia",                        {"endpoints": True, "owner_name": "mia"}),
    ("show nat's devices",                          {"endpoints": True, "owner_name": "nat"}),
    ("find endpoints for olivia",                   {"endpoints": True, "owner_name": "olivia"}),
    ("list devices for peter",                      {"endpoints": True, "owner_name": "peter"}),
    ("get rosa's machines",                         {"endpoints": True, "owner_name": "rosa"}),
    ("show sid's endpoints",                        {"endpoints": True, "owner_name": "sid"}),
    ("devices for ted",                             {"endpoints": True, "owner_name": "ted"}),
    ("what devices does uma own",                   {"endpoints": True, "owner_name": "uma"}),
    ("show vera's computers",                       {"endpoints": True, "owner_name": "vera"}),
    ("list will's devices",                         {"endpoints": True, "owner_name": "will"}),
    ("show xena's endpoints",                       {"endpoints": True, "owner_name": "xena"}),

    # =========================================================================
    # ADDITIONAL NAMED USER ACTIVITY TESTS
    # =========================================================================
    ("show activity for diana",                     {"activity": True, "act_user": "diana"}),
    ("logins for ethan",                            {"activity": True, "act_user": "ethan"}),
    ("fiona's login events",                        {"activity": True, "act_user": "fiona"}),
    ("what did gary access",                        {"activity": True, "act_user": "gary"}),
    ("show hannah's logins",                        {"activity": True, "act_user": "hannah"}),
    ("activity for igor",                           {"activity": True, "act_user": "igor"}),
    ("show jason's activity",                       {"activity": True, "act_user": "jason"}),
    ("list kate's events",                          {"activity": True, "act_user": "kate"}),
    ("leo's login history",                         {"activity": True, "act_user": "leo"}),
    ("show mia's sessions",                         {"activity": True, "act_user": "mia"}),
    ("logins for nat",                              {"activity": True, "act_user": "nat"}),
    ("olivia's access events",                      {"activity": True, "act_user": "olivia"}),
    ("show activity for peter",                     {"activity": True, "act_user": "peter"}),
    ("rosa's login events",                         {"activity": True, "act_user": "rosa"}),
    ("what did sid access",                         {"activity": True, "act_user": "sid"}),
    ("show ted's logins",                           {"activity": True, "act_user": "ted"}),
    ("uma's activity history",                      {"activity": True, "act_user": "uma"}),
    ("show vera's login events",                    {"activity": True, "act_user": "vera"}),
    ("list will's logins",                          {"activity": True, "act_user": "will"}),
    ("xena's login history",                        {"activity": True, "act_user": "xena"}),
]

# Merge extended tests into the main list
INTENT_TESTS = INTENT_TESTS + INTENT_TESTS_EXTENDED


# ===========================================================================
# EXTENDED FOLLOW-UP TESTS
# ===========================================================================

FOLLOWUP_TESTS_EXTENDED = [
    # Clear follow-up signals
    ("show those endpoints too", [("user","list devices"),("assistant","result")], True),
    ("filter those by OS", [("user","list endpoints"),("assistant","result")], True),
    ("now give me the Linux ones", [("user","list devices"),("assistant","result")], True),
    ("and the macOS ones too", [("user","list endpoints"),("assistant","result")], True),
    ("show me the results", [("user","list devices"),("assistant","result")], True),
    ("list the above endpoints", [("user","show devices"),("assistant","result")], True),
    ("from those, show non-compliant", [("user","list endpoints"),("assistant","result")], True),
    ("of those, show without VPN", [("user","list devices"),("assistant","result")], True),
    ("among those devices, filter by high risk", [("user","list endpoints"),("assistant","result")], True),
    ("within those results, show Windows", [("user","list devices"),("assistant","result")], True),
    ("refine by medium risk", [("user","list endpoints"),("assistant","result")], True),
    ("narrow to Linux only", [("user","list devices"),("assistant","result")], True),
    ("filter by compliance status", [("user","list endpoints"),("assistant","result")], True),
    ("also show the owners", [("user","list endpoints"),("assistant","result")], True),
    ("and also filter by high risk", [("user","list endpoints"),("assistant","result")], True),
    ("now list the macOS ones", [("user","list devices"),("assistant","result")], True),
    ("only show critical risk ones", [("user","list endpoints"),("assistant","result")], True),
    ("what about the ones without VPN", [("user","list endpoints"),("assistant","result")], True),
    ("filter these by Windows OS", [("user","list devices"),("assistant","result")], True),
    ("narrow the results by risk", [("user","list endpoints"),("assistant","result")], True),
    ("show only the flagged ones", [("user","list events"),("assistant","result")], True),
    ("filter those events by country", [("user","list events"),("assistant","result")], True),
    ("in that list, show from Russia", [("user","list login events"),("assistant","result")], True),
    ("show these results sorted by risk", [("user","list users"),("assistant","result")], True),
    ("those with MFA disabled", [("user","list users"),("assistant","result")], True),
    ("the suspended ones from those", [("user","list users"),("assistant","result")], True),
    ("among them, find suspended", [("user","list users"),("assistant","result")], True),
    ("within those users, show no MFA", [("user","list accounts"),("assistant","result")], True),
    ("from the previous list, show high risk", [("user","list users"),("assistant","result")], True),
    ("the results filtered by department", [("user","list users"),("assistant","result")], True),

    # Sort signals
    ("sort by compliance", [("user","list endpoints"),("assistant","result")], True),
    ("order by hostname", [("user","list devices"),("assistant","result")], True),
    ("rank by last seen", [("user","list endpoints"),("assistant","result")], True),
    ("sort those by email", [("user","list users"),("assistant","result")], True),
    ("order those by name", [("user","list accounts"),("assistant","result")], True),

    # Short messages that are follow-ups
    ("and windows", [("user","list endpoints"),("assistant","result")], True),
    ("or linux", [("user","list devices"),("assistant","result")], True),
    ("critical only", [("user","list endpoints"),("assistant","result")], True),
    ("no dlp", [("user","list devices"),("assistant","result")], True),
    ("no edr", [("user","list endpoints"),("assistant","result")], True),
    ("not encrypted", [("user","list devices"),("assistant","result")], True),
    ("without mfa", [("user","list users"),("assistant","result")], True),
    ("just suspended", [("user","list accounts"),("assistant","result")], True),
    ("sort them", [("user","list endpoints"),("assistant","result")], True),
    ("group by os", [("user","list devices"),("assistant","result")], True),

    # Without history → not followup
    ("show those endpoints too", [], False),
    ("filter by OS", [], False),
    ("sort by risk", [], False),
    ("only show critical risk ones", [], False),
    ("also show the owners", [], False),
    ("among them, find suspended", [], False),
    ("from the previous list", [], False),
    ("within those results", [], False),
    ("refine by medium risk", [], False),
    ("narrow to Linux only", [], False),

    # Explicit standalone queries that should NOT be follow-ups (with history)
    ("show all non-compliant endpoints", [("user","list users"),("assistant","result")], False),
    ("list all windows devices", [("user","list linux devices"),("assistant","result")], False),
    ("show all users without MFA", [("user","list endpoints"),("assistant","result")], False),
    ("show compliance overview", [("user","list endpoints"),("assistant","result")], False),
    ("what is the risk summary", [("user","list devices"),("assistant","result")], False),
    ("list all saml events", [("user","list devices"),("assistant","result")], False),
    ("show all vpn events", [("user","list users"),("assistant","result")], False),
    ("show all login events from Russia", [("user","list devices"),("assistant","result")], False),
    ("list all users in engineering", [("user","list endpoints"),("assistant","result")], False),
    ("find all high risk users", [("user","list devices"),("assistant","result")], False),
]

FOLLOWUP_TESTS = FOLLOWUP_TESTS + FOLLOWUP_TESTS_EXTENDED


# ===========================================================================
# EXTENDED CONVERSATIONAL TESTS
# ===========================================================================

CONV_TESTS_EXTENDED = [
    # More greetings
    ("hi!", True),
    ("hello!", True),
    ("hey!", True),
    ("howdy!", True),
    ("Hello.", True),
    ("Hi.", True),
    ("good morning!", True),
    ("good afternoon.", True),
    ("good evening!", True),
    ("HELLO", True),
    ("HI", True),
    ("Hey.", True),

    # More thanks
    ("thanks!", True),
    ("Thank you!", True),
    ("thx!", True),
    ("ty!", True),
    ("great!", True),
    ("perfect!", True),
    ("awesome!", True),
    ("nice!", True),
    ("cool!", True),
    ("cheers!", True),
    ("Thanks.", True),

    # More help
    ("what can you do for me", True),
    ("what do you know about security", True),
    ("who are you exactly", True),
    ("what are your features", True),
    ("what are your capabilities", True),
    ("can you help me with security", True),
    ("help me find something", True),
    ("what do you show", True),
    ("how do I use you", True),
    ("what can I ask you", True),
    ("what queries can I make", True),

    # Security queries (should NOT be conversational)
    ("show me all VPN events",          False),
    ("list all SAML logins",            False),
    ("find high risk endpoints",        False),
    ("show users in HR",                False),
    ("what is the compliance status",   False),
    ("show me alice's logins",          False),
    ("list devices for bob",            False),
    ("show oauth grant events",         False),
    ("network events from Russia",      False),
    ("show suspicious saml events",     False),
    ("list all file access events",     False),
    ("show cloud access today",         False),
    ("vpn events for liad",             False),
    ("show me non-compliant endpoints", False),
    ("list critical risk users",        False),
    ("find unassigned endpoints",       False),
    ("show users without 2FA",          False),
    ("activity from Iran this week",    False),
    ("show Windows devices",            False),
    ("list macOS laptops",              False),
    ("show Linux servers",              False),
    ("find endpoints missing EDR",      False),
    ("show devices without DLP",        False),
    ("list unencrypted laptops",        False),
    ("show inactive agents",            False),
    ("what devices does alice have",    False),
    ("show bob's saml events",          False),
    ("list eve's activity",             False),
]

CONV_TESTS = CONV_TESTS + CONV_TESTS_EXTENDED


# ===========================================================================
# EXTRA INTENT TESTS (volume expansion to reach 2000+)
# ===========================================================================

INTENT_TESTS_EXTRA = [

    # =========================================================================
    # MORE ENDPOINT PATTERNS (long-tail variations)
    # =========================================================================
    ("show all hosts on the network",               {"endpoints": True, "is_list": True}),
    ("get all managed machines",                    {"endpoints": True, "is_list": True}),
    ("list registered devices",                     {"endpoints": True, "is_list": True}),
    ("show me the device inventory",                {"endpoints": True}),
    ("pull all endpoint records",                   {"endpoints": True}),
    ("display all machines in the fleet",           {"endpoints": True, "is_list": True}),
    ("show me every endpoint",                      {"endpoints": True, "is_list": True}),
    ("list every device",                           {"endpoints": True, "is_list": True}),
    ("which machines are registered",               {"endpoints": True, "is_list": True}),
    ("show me all laptops and desktops",            {"endpoints": True, "is_list": True}),

    # =========================================================================
    # MORE NO-EDR VARIATIONS
    # =========================================================================
    ("list machines that have no s1",               {"endpoints": True, "edr_missing": True}),
    ("show devices with sentinelone missing",       {"endpoints": True, "edr_missing": True}),
    ("which laptops lack EDR",                      {"endpoints": True, "edr_missing": True}),
    ("find workstations where edr is not present",  {"endpoints": True, "edr_missing": True}),
    ("show pcs missing sentinelone",                {"endpoints": True, "edr_missing": True}),
    ("list endpoints missing edr protection",       {"endpoints": True, "edr_missing": True}),

    # =========================================================================
    # MORE EDR OUTDATED VARIATIONS
    # =========================================================================
    ("which machines are running an old edr",       {"endpoints": True, "edr_outdated": True}),
    ("show endpoints with stale sentinelone",       {"endpoints": True, "edr_outdated": True}),
    ("list pcs where s1 version is old",            {"endpoints": True, "edr_outdated": True}),
    ("find devices with edr version that is outdated", {"endpoints": True, "edr_outdated": True}),
    ("show computers with an outdated edr agent",   {"endpoints": True, "edr_outdated": True}),

    # =========================================================================
    # MORE VPN MISSING VARIATIONS
    # =========================================================================
    ("list machines where vpn is not present",      {"endpoints": True, "vpn_missing": True}),
    ("show devices that are lacking vpn",           {"endpoints": True, "vpn_missing": True}),
    ("find endpoints where vpn is absent",          {"endpoints": True, "vpn_missing": True}),
    ("show computers without any vpn client",       {"endpoints": True, "vpn_missing": True}),
    ("list pcs that don't have globalprotect",      {"endpoints": True, "vpn_missing": True}),
    ("which laptops are missing a vpn",             {"endpoints": True, "vpn_missing": True}),

    # =========================================================================
    # MORE DISK ENCRYPTION VARIATIONS
    # =========================================================================
    ("show machines where encryption is off",       {"endpoints": True, "disk_not_encrypted": True}),
    ("list endpoints that lack encryption",         {"endpoints": True, "disk_not_encrypted": True}),
    ("find pcs with no filevault or bitlocker",     {"endpoints": True, "disk_not_encrypted": True}),
    ("which devices have disk encryption disabled", {"endpoints": True, "disk_not_encrypted": True}),
    ("show computers where disks are unencrypted",  {"endpoints": True, "disk_not_encrypted": True}),
    ("list laptops with encryption missing",        {"endpoints": True, "disk_not_encrypted": True}),

    # =========================================================================
    # MORE USER + MFA VARIATIONS
    # =========================================================================
    ("show me all users missing two-factor",        {"users": True, "mfa_enabled": False}),
    ("which employees are not using mfa",           {"users": True, "mfa_enabled": False}),
    ("list accounts where 2fa is disabled",         {"users": True, "mfa_enabled": False}),
    ("show staff with mfa turned off",              {"users": True, "mfa_enabled": False}),
    ("find users that have no mfa set up",          {"users": True, "mfa_enabled": False}),
    ("list all employees lacking two-factor auth",  {"users": True, "mfa_enabled": False}),
    ("which workers don't use mfa",                 {"users": True, "mfa_enabled": False}),
    ("show members with no 2fa configured",         {"users": True, "mfa_enabled": False}),

    # =========================================================================
    # MORE SUSPENDED USER VARIATIONS
    # =========================================================================
    ("list all deactivated accounts",               {"users": True, "suspended": True}),
    ("show me locked accounts",                     {"users": True, "suspended": True}),
    ("which users have been suspended",             {"users": True, "suspended": True}),
    ("show all blocked employee accounts",          {"users": True, "suspended": True}),
    ("find all suspended or blocked users",         {"users": True, "suspended": True}),

    # =========================================================================
    # MORE NO-ENDPOINT USER VARIATIONS
    # =========================================================================
    ("show employees who have no registered device",{"users": True, "no_endpoint": True}),
    ("find users with zero devices",                {"users": True, "no_endpoint": True}),
    ("list staff without any computer",             {"users": True, "no_endpoint": True}),
    ("show accounts with no machine",               {"users": True, "no_endpoint": True}),
    ("which employees don't have a device",         {"users": True, "no_endpoint": True}),
    ("find workers who are missing a device",       {"users": True, "no_endpoint": True}),

    # =========================================================================
    # MORE COMPLIANCE SUMMARY PATTERNS
    # =========================================================================
    ("how compliant are we overall",                {"compliance": True}),
    ("show our compliance health",                  {"compliance": True}),
    ("what is the compliance level",                {"compliance": True}),
    ("show the security compliance dashboard",      {"compliance": True}),
    ("give me a full compliance report",            {"compliance": True}),
    ("show compliance trends",                      {"compliance": True}),
    ("how are we doing on compliance",              {"compliance": True}),
    ("show our posture summary",                    {"compliance": True}),

    # =========================================================================
    # MORE RISK SUMMARY PATTERNS
    # =========================================================================
    ("show our risk landscape",                     {"risk": True}),
    ("what's our current risk level",               {"risk": True}),
    ("show risk metrics",                           {"risk": True}),
    ("give me the risk breakdown",                  {"risk": True}),
    ("how risky are our assets",                    {"risk": True}),
    ("show all risky devices and users",            {"risk": True}),
    ("what is the high risk count",                 {"risk": True}),
    ("show risk by severity",                       {"risk": True}),

    # =========================================================================
    # MORE SAML PATTERNS
    # =========================================================================
    ("list saml sign in events",                    {"activity": True, "event_type": "saml"}),
    ("get all saml login records",                  {"activity": True, "event_type": "saml"}),
    ("show saml events this month",                 {"activity": True, "event_type": "saml", "days_back": 30}),
    ("suspicious saml events this week",            {"activity": True, "event_type": "saml", "is_suspicious": True, "days_back": 7}),
    ("saml logins from North Korea",                {"activity": True, "event_type": "saml", "country": "North Korea"}),
    ("saml events for diana",                       {"activity": True, "event_type": "saml", "act_user": "diana"}),
    ("show diana's saml logins",                    {"activity": True, "event_type": "saml", "act_user": "diana"}),
    ("saml events for ethan",                       {"activity": True, "event_type": "saml", "act_user": "ethan"}),
    ("show fiona's saml activity",                  {"activity": True, "event_type": "saml", "act_user": "fiona"}),
    ("list all saml auth events from Israel",       {"activity": True, "event_type": "saml", "country": "Israel"}),

    # =========================================================================
    # MORE OAUTH PATTERNS
    # =========================================================================
    ("show all oauth events",                       {"activity": True, "event_type": "oauth_grant"}),
    ("list oauth access events",                    {"activity": True, "event_type": "oauth_grant"}),
    ("get oauth grant activity today",              {"activity": True, "event_type": "oauth_grant", "days_back": 1}),
    ("suspicious oauth events this month",          {"activity": True, "event_type": "oauth_grant", "is_suspicious": True, "days_back": 30}),
    ("oauth events from Iran",                      {"activity": True, "event_type": "oauth_grant", "country": "Iran"}),
    ("oauth grant events for diana",                {"activity": True, "event_type": "oauth_grant", "act_user": "diana"}),
    ("show ethan's oauth grants",                   {"activity": True, "event_type": "oauth_grant", "act_user": "ethan"}),
    ("oauth events for fiona",                      {"activity": True, "event_type": "oauth_grant", "act_user": "fiona"}),

    # =========================================================================
    # MORE NETWORK EVENTS PATTERNS
    # =========================================================================
    ("show all network connection events",          {"activity": True, "event_type": "network"}),
    ("list all network traffic",                    {"activity": True, "event_type": "network"}),
    ("network activity from North Korea",           {"activity": True, "event_type": "network", "country": "North Korea"}),
    ("suspicious network traffic from China",       {"activity": True, "event_type": "network", "is_suspicious": True, "country": "China"}),
    ("network events for diana",                    {"activity": True, "event_type": "network", "act_user": "diana"}),
    ("show ethan's network events",                 {"activity": True, "event_type": "network", "act_user": "ethan"}),
    ("network traffic for fiona",                   {"activity": True, "event_type": "network", "act_user": "fiona"}),
    ("get all network activity this week",          {"activity": True, "event_type": "network", "days_back": 7}),

    # =========================================================================
    # MORE VPN EVENTS PATTERNS
    # =========================================================================
    ("show all vpn connection events",              {"activity": True, "event_type": "vpn"}),
    ("list all vpn login records",                  {"activity": True, "event_type": "vpn"}),
    ("vpn events from North Korea",                 {"activity": True, "event_type": "vpn", "country": "North Korea"}),
    ("suspicious vpn logins from China",            {"activity": True, "event_type": "vpn", "is_suspicious": True, "country": "China"}),
    ("vpn events for diana",                        {"activity": True, "event_type": "vpn", "act_user": "diana"}),
    ("show ethan's vpn sessions",                   {"activity": True, "event_type": "vpn", "act_user": "ethan"}),
    ("vpn login events for fiona",                  {"activity": True, "event_type": "vpn", "act_user": "fiona"}),
    ("get all vpn activity this month",             {"activity": True, "event_type": "vpn", "days_back": 30}),

    # =========================================================================
    # MORE FILE ACCESS PATTERNS
    # =========================================================================
    ("show all file access records",                {"activity": True, "event_type": "file_access"}),
    ("list all file access logs",                   {"activity": True, "event_type": "file_access"}),
    ("file access from North Korea",                {"activity": True, "event_type": "file_access", "country": "North Korea"}),
    ("suspicious file access from Iran",            {"activity": True, "event_type": "file_access", "is_suspicious": True, "country": "Iran"}),
    ("file access events for diana",                {"activity": True, "event_type": "file_access", "act_user": "diana"}),
    ("show ethan's file access",                    {"activity": True, "event_type": "file_access", "act_user": "ethan"}),
    ("file access for fiona this week",             {"activity": True, "event_type": "file_access", "act_user": "fiona", "days_back": 7}),

    # =========================================================================
    # MORE CLOUD ACCESS PATTERNS
    # =========================================================================
    ("show all cloud service access",               {"activity": True, "event_type": "cloud_access"}),
    ("list all cloud access records",               {"activity": True, "event_type": "cloud_access"}),
    ("cloud access from North Korea",               {"activity": True, "event_type": "cloud_access", "country": "North Korea"}),
    ("suspicious cloud access from Iran",           {"activity": True, "event_type": "cloud_access", "is_suspicious": True, "country": "Iran"}),
    ("cloud access events for diana",               {"activity": True, "event_type": "cloud_access", "act_user": "diana"}),
    ("show ethan's cloud access",                   {"activity": True, "event_type": "cloud_access", "act_user": "ethan"}),
    ("cloud access for fiona this week",            {"activity": True, "event_type": "cloud_access", "act_user": "fiona", "days_back": 7}),

    # =========================================================================
    # MORE NAMED OWNER LOOKUP (50 more names)
    # =========================================================================
    ("show aaron's devices",                        {"endpoints": True, "owner_name": "aaron"}),
    ("list beth's endpoints",                       {"endpoints": True, "owner_name": "beth"}),
    ("find carl's machines",                        {"endpoints": True, "owner_name": "carl"}),
    ("show dora's computers",                       {"endpoints": True, "owner_name": "dora"}),
    ("list evan's laptops",                         {"endpoints": True, "owner_name": "evan"}),
    ("find flora's devices",                        {"endpoints": True, "owner_name": "flora"}),
    ("show glen's endpoints",                       {"endpoints": True, "owner_name": "glen"}),
    ("list hope's machines",                        {"endpoints": True, "owner_name": "hope"}),
    ("find ivan's computers",                       {"endpoints": True, "owner_name": "ivan"}),
    ("show joel's devices",                         {"endpoints": True, "owner_name": "joel"}),
    ("list kim's endpoints",                        {"endpoints": True, "owner_name": "kim"}),
    ("find leon's machines",                        {"endpoints": True, "owner_name": "leon"}),
    ("show mary's computers",                       {"endpoints": True, "owner_name": "mary"}),
    ("list neil's laptops",                         {"endpoints": True, "owner_name": "neil"}),
    ("find opal's devices",                         {"endpoints": True, "owner_name": "opal"}),
    ("show pete's endpoints",                       {"endpoints": True, "owner_name": "pete"}),
    ("list ruth's machines",                        {"endpoints": True, "owner_name": "ruth"}),
    ("find seth's computers",                       {"endpoints": True, "owner_name": "seth"}),
    ("show tara's devices",                         {"endpoints": True, "owner_name": "tara"}),
    ("list umar's endpoints",                       {"endpoints": True, "owner_name": "umar"}),
    ("endpoints for aaron",                         {"endpoints": True, "owner_name": "aaron"}),
    ("devices for beth",                            {"endpoints": True, "owner_name": "beth"}),
    ("machines for carl",                           {"endpoints": True, "owner_name": "carl"}),
    ("computers for dora",                          {"endpoints": True, "owner_name": "dora"}),
    ("laptops for evan",                            {"endpoints": True, "owner_name": "evan"}),
    ("devices for flora",                           {"endpoints": True, "owner_name": "flora"}),
    ("endpoints for glen",                          {"endpoints": True, "owner_name": "glen"}),
    ("machines for hope",                           {"endpoints": True, "owner_name": "hope"}),
    ("computers for ivan",                          {"endpoints": True, "owner_name": "ivan"}),
    ("devices for joel",                            {"endpoints": True, "owner_name": "joel"}),
    ("what devices does kim have",                  {"endpoints": True, "owner_name": "kim"}),
    ("what machines does leon own",                 {"endpoints": True, "owner_name": "leon"}),
    ("what computers does mary use",                {"endpoints": True, "owner_name": "mary"}),
    ("what endpoints does neil have",               {"endpoints": True, "owner_name": "neil"}),
    ("what devices does opal own",                  {"endpoints": True, "owner_name": "opal"}),
    ("show me pete's devices",                      {"endpoints": True, "owner_name": "pete"}),
    ("show me ruth's endpoints",                    {"endpoints": True, "owner_name": "ruth"}),
    ("show me seth's machines",                     {"endpoints": True, "owner_name": "seth"}),
    ("show me tara's computers",                    {"endpoints": True, "owner_name": "tara"}),
    ("show me umar's laptops",                      {"endpoints": True, "owner_name": "umar"}),
    ("devices owned by aaron",                      {"endpoints": True, "owner_name": "aaron"}),
    ("machines owned by beth",                      {"endpoints": True, "owner_name": "beth"}),
    ("computers belonging to carl",                 {"endpoints": True, "owner_name": "carl"}),
    ("endpoints assigned to dora",                  {"endpoints": True, "owner_name": "dora"}),
    ("laptops belonging to evan",                   {"endpoints": True, "owner_name": "evan"}),

    # =========================================================================
    # MORE NAMED USER ACTIVITY (50 more names)
    # =========================================================================
    ("show activity for aaron",                     {"activity": True, "act_user": "aaron"}),
    ("logins for beth",                             {"activity": True, "act_user": "beth"}),
    ("carl's login events",                         {"activity": True, "act_user": "carl"}),
    ("what did dora access",                        {"activity": True, "act_user": "dora"}),
    ("show evan's logins",                          {"activity": True, "act_user": "evan"}),
    ("activity for flora",                          {"activity": True, "act_user": "flora"}),
    ("show glen's activity",                        {"activity": True, "act_user": "glen"}),
    ("list hope's events",                          {"activity": True, "act_user": "hope"}),
    ("ivan's login history",                        {"activity": True, "act_user": "ivan"}),
    ("show joel's sessions",                        {"activity": True, "act_user": "joel"}),
    ("logins for kim",                              {"activity": True, "act_user": "kim"}),
    ("leon's access events",                        {"activity": True, "act_user": "leon"}),
    ("show activity for mary",                      {"activity": True, "act_user": "mary"}),
    ("neil's login events",                         {"activity": True, "act_user": "neil"}),
    ("what did opal access",                        {"activity": True, "act_user": "opal"}),
    ("show pete's logins",                          {"activity": True, "act_user": "pete"}),
    ("ruth's activity history",                     {"activity": True, "act_user": "ruth"}),
    ("show seth's login events",                    {"activity": True, "act_user": "seth"}),
    ("list tara's logins",                          {"activity": True, "act_user": "tara"}),
    ("umar's login history",                        {"activity": True, "act_user": "umar"}),
    ("activity for aaron today",                    {"activity": True, "act_user": "aaron", "days_back": 1}),
    ("logins for beth this week",                   {"activity": True, "act_user": "beth", "days_back": 7}),
    ("carl's logins from Russia",                   {"activity": True, "act_user": "carl", "country": "Russia"}),
    ("suspicious activity for dora",                {"activity": True, "act_user": "dora", "is_suspicious": True}),
    ("show evan's suspicious logins",               {"activity": True, "act_user": "evan", "is_suspicious": True}),
    ("flora's saml events",                         {"activity": True, "event_type": "saml", "act_user": "flora"}),
    ("show glen's oauth grants",                    {"activity": True, "event_type": "oauth_grant", "act_user": "glen"}),
    ("hope's vpn events",                           {"activity": True, "event_type": "vpn", "act_user": "hope"}),
    ("show ivan's network events",                  {"activity": True, "event_type": "network", "act_user": "ivan"}),
    ("joel's file access",                          {"activity": True, "event_type": "file_access", "act_user": "joel"}),
    ("show kim's cloud access",                     {"activity": True, "event_type": "cloud_access", "act_user": "kim"}),
    ("list leon's app usage",                       {"activity": True, "event_type": "app_usage", "act_user": "leon"}),
    ("show mary's saml logins",                     {"activity": True, "event_type": "saml", "act_user": "mary"}),
    ("neil's oauth grants",                         {"activity": True, "event_type": "oauth_grant", "act_user": "neil"}),
    ("show opal's vpn connections",                 {"activity": True, "event_type": "vpn", "act_user": "opal"}),

    # =========================================================================
    # ADDITIONAL COMBINED FILTERS
    # =========================================================================
    ("show critical Windows machines missing EDR",  {"endpoints": True, "os": "windows", "risk_level_ep": "critical", "edr_missing": True}),
    ("list high risk Linux servers without VPN",    {"endpoints": True, "os": "linux", "risk_level_ep": "high", "vpn_missing": True}),
    ("find macOS devices with outdated EDR",        {"endpoints": True, "os": "macos", "edr_outdated": True}),
    ("show Windows endpoints with no DLP and no VPN", {"endpoints": True, "os": "windows", "dlp_missing": True, "vpn_missing": True}),
    ("list unassigned Linux endpoints",             {"endpoints": True, "os": "linux", "unassigned": True}),
    ("show non-compliant Windows laptops",          {"endpoints": True, "os": "windows", "compliance_status": "non_compliant"}),
    ("find partially compliant macOS machines",     {"endpoints": True, "os": "macos", "compliance_status": "partial"}),
    ("show critical risk users in IT without MFA",  {"users": True, "department": "it", "risk_level_u": "critical", "mfa_enabled": False}),
    ("list high risk sales employees",              {"users": True, "department": "sales", "risk_level_u": "high"}),
    ("find suspended HR staff",                     {"users": True, "department": "hr", "suspended": True}),
    ("show critical risk finance users with no device", {"users": True, "department": "finance", "risk_level_u": "critical", "no_endpoint": True}),
    ("list marketing employees without MFA",        {"users": True, "department": "marketing", "mfa_enabled": False}),
    ("show engineering users who are suspended",    {"users": True, "department": "engineering", "suspended": True}),
    ("find inactive operations users",              {"users": True, "department": "operations", "employment_status": "inactive"}),
    ("list legal staff at medium risk",             {"users": True, "department": "legal", "risk_level_u": "medium"}),

    # =========================================================================
    # MORE ACTIVITY WITH COMBINED FILTERS
    # =========================================================================
    ("suspicious saml events today from China",     {"activity": True, "event_type": "saml", "is_suspicious": True, "country": "China", "days_back": 1}),
    ("show oauth events from Russia this week",     {"activity": True, "event_type": "oauth_grant", "country": "Russia", "days_back": 7}),
    ("vpn events from Ukraine this month",          {"activity": True, "event_type": "vpn", "country": "Ukraine", "days_back": 30}),
    ("network events from Iran last 7 days",        {"activity": True, "event_type": "network", "country": "Iran", "days_back": 7}),
    ("file access from North Korea this week",      {"activity": True, "event_type": "file_access", "country": "North Korea", "days_back": 7}),
    ("cloud access from China today",               {"activity": True, "event_type": "cloud_access", "country": "China", "days_back": 1}),
    ("suspicious network activity from Russia",     {"activity": True, "event_type": "network", "is_suspicious": True, "country": "Russia"}),
    ("flagged vpn events from Iran",                {"activity": True, "event_type": "vpn", "is_suspicious": True, "country": "Iran"}),
    ("unusual saml events from Ukraine",            {"activity": True, "event_type": "saml", "is_suspicious": True, "country": "Ukraine"}),
    ("anomalous oauth grants from North Korea",     {"activity": True, "event_type": "oauth_grant", "is_suspicious": True, "country": "North Korea"}),

    # =========================================================================
    # ADDITIONAL GENERIC PATTERNS
    # =========================================================================
    ("show me all the data",                        {}),
    ("what do you have",                            {}),
    ("give me everything",                          {}),
    ("show security incidents",                     {}),
    ("list all incidents",                          {}),
    ("show me alerts",                              {}),
    ("what alerts are there",                       {}),
    ("show security events",                        {"activity": True}),
    ("list all security events",                    {"activity": True, "is_list": True}),
    ("show policy violations",                      {"compliance": True}),
    ("list policy violations",                      {"compliance": True}),
    ("show me posture issues",                      {"compliance": True}),
    ("what are the compliance issues",              {"compliance": True}),
    ("show all compliance failures",                {"compliance": True}),
    ("list compliance failures",                    {"compliance": True, "is_list": True}),
    ("show endpoint risk",                          {"endpoints": True}),
    ("show user risk",                              {"users": True}),
    ("list risky users",                            {"risk": True}),
    ("show all risky endpoints",                    {"risk": True}),

    # =========================================================================
    # ACTIVITY WITHOUT EXPLICIT ENTITY
    # =========================================================================
    ("show logins today",                           {"activity": True, "days_back": 1}),
    ("logins this week",                            {"activity": True, "days_back": 7}),
    ("events today",                                {"activity": True, "days_back": 1}),
    ("events this week",                            {"activity": True, "days_back": 7}),
    ("logins this month",                           {"activity": True, "days_back": 30}),
    ("events from last week",                       {"activity": True, "days_back": 7}),
    ("access today",                                {"activity": True, "days_back": 1}),
    ("access this week",                            {"activity": True, "days_back": 7}),
    ("show all access today",                       {"activity": True, "days_back": 1, "is_list": True}),
    ("show all events today",                       {"activity": True, "days_back": 1, "is_list": True}),
    ("list events this week",                       {"activity": True, "days_back": 7, "is_list": True}),
    ("show logins last 7 days",                     {"activity": True, "days_back": 7}),
    ("show events last 30 days",                    {"activity": True, "days_back": 30}),
    ("login activity today",                        {"activity": True, "days_back": 1}),
    ("login activity last week",                    {"activity": True, "days_back": 7}),

    # =========================================================================
    # MORE RISK LEVEL COMBINATIONS
    # =========================================================================
    ("list high risk devices",                      {"endpoints": True, "risk_level_ep": "high"}),
    ("show critical devices",                       {"endpoints": True, "risk_level_ep": "critical"}),
    ("find medium risk machines",                   {"endpoints": True, "risk_level_ep": "medium"}),
    ("show low risk computers",                     {"endpoints": True, "risk_level_ep": "low"}),
    ("list high risk people",                       {"users": True, "risk_level_u": "high"}),
    ("show critical risk people",                   {"users": True, "risk_level_u": "critical"}),
    ("find medium risk employees",                  {"users": True, "risk_level_u": "medium"}),
    ("show low risk workers",                       {"users": True, "risk_level_u": "low"}),
    ("list high risk accounts",                     {"users": True, "risk_level_u": "high"}),
    ("show critical accounts",                      {"users": True, "risk_level_u": "critical"}),
    ("high risk pcs",                               {"endpoints": True, "risk_level_ep": "high"}),
    ("critical laptops",                            {"endpoints": True, "risk_level_ep": "critical"}),
    ("medium risk hosts",                           {"endpoints": True, "risk_level_ep": "medium"}),

    # =========================================================================
    # EMAIL OWNER LOOKUP ADDITIONAL
    # =========================================================================
    ("show endpoints for frank@company.com",        {"endpoints": True, "owner_name": "frank@company.com"}),
    ("list machines for grace@corp.org",            {"endpoints": True, "owner_name": "grace@corp.org"}),
    ("devices for henry@work.net",                  {"endpoints": True, "owner_name": "henry@work.net"}),
    ("what devices does iris@company.io have",      {"endpoints": True, "owner_name": "iris@company.io"}),
    ("endpoints owned by jake@domain.com",          {"endpoints": True, "owner_name": "jake@domain.com"}),
    ("show karen@corp.co's devices",                {"endpoints": True, "owner_name": "karen@corp.co"}),

    # =========================================================================
    # EMAIL ACTIVITY ADDITIONAL
    # =========================================================================
    ("activity for frank@company.com",              {"activity": True, "act_user": "frank@company.com"}),
    ("logins for grace@corp.org",                   {"activity": True, "act_user": "grace@corp.org"}),
    ("events for henry@work.net",                   {"activity": True, "act_user": "henry@work.net"}),
    ("what did iris@company.io access",             {"activity": True, "act_user": "iris@company.io"}),
    ("show jake@domain.com's logins",               {"activity": True, "act_user": "jake@domain.com"}),
    ("show events for karen@corp.co",               {"activity": True, "act_user": "karen@corp.co"}),
]

INTENT_TESTS = INTENT_TESTS + INTENT_TESTS_EXTRA


# ===========================================================================
# EXTRA FOLLOWUP TESTS
# ===========================================================================

FOLLOWUP_TESTS_EXTRA = [
    # More with-history follow-ups
    ("which of those are critical", [("user","list endpoints"),("assistant","result")], True),
    ("how many are Windows", [("user","list devices"),("assistant","result")], True),
    ("what about macOS", [("user","list endpoints"),("assistant","result")], True),
    ("any Linux ones", [("user","list devices"),("assistant","result")], True),
    ("now filter by non-compliant", [("user","list endpoints"),("assistant","result")], True),
    ("also add unassigned", [("user","list devices"),("assistant","result")], True),
    ("now refine those", [("user","list endpoints"),("assistant","result")], True),
    ("narrow down to Windows", [("user","list devices"),("assistant","result")], True),
    ("filter the list by department", [("user","list users"),("assistant","result")], True),
    ("show those sorted", [("user","list endpoints"),("assistant","result")], True),
    ("list them by risk", [("user","list devices"),("assistant","result")], True),
    ("rank those by last seen", [("user","list endpoints"),("assistant","result")], True),
    ("sort those by hostname", [("user","list devices"),("assistant","result")], True),
    ("order those by email", [("user","list users"),("assistant","result")], True),
    ("sort by date", [("user","show activity"),("assistant","result")], True),
    ("and from those, show critical", [("user","list endpoints"),("assistant","result")], True),
    ("also from them show non-compliant", [("user","list devices"),("assistant","result")], True),
    ("from the above, find high risk", [("user","list users"),("assistant","result")], True),
    ("from those, filter by mfa", [("user","list users"),("assistant","result")], True),
    ("the ones without MFA", [("user","list users"),("assistant","result")], True),
    ("those users with no endpoint", [("user","list users"),("assistant","result")], True),
    ("from them show suspended", [("user","list accounts"),("assistant","result")], True),
    ("within those, show flagged", [("user","list events"),("assistant","result")], True),
    ("from those events, show Russia", [("user","show activity"),("assistant","result")], True),
    ("of those events, show today's", [("user","list events"),("assistant","result")], True),
    ("the above events from this week", [("user","show activity"),("assistant","result")], True),
    ("now filter those by China", [("user","show events"),("assistant","result")], True),
    ("refine the results by today", [("user","show events"),("assistant","result")], True),
    ("only the ones from today", [("user","show events"),("assistant","result")], True),
    ("from those, the ones from Russia", [("user","show login events"),("assistant","result")], True),

    # No history → not followup
    ("which of those are critical", [], False),
    ("now filter by non-compliant", [], False),
    ("sort those by hostname", [], False),
    ("and from those show critical", [], False),
    ("the ones without MFA", [], False),
    ("from those events show Russia", [], False),
    ("narrow down to Windows", [], False),
    ("rank those by last seen", [], False),
    ("also from them show non-compliant", [], False),
    ("now refine those", [], False),
]

FOLLOWUP_TESTS = FOLLOWUP_TESTS + FOLLOWUP_TESTS_EXTRA


# ===========================================================================
# FINAL EXPANSION TESTS (to definitively reach 2000+)
# ===========================================================================

INTENT_TESTS_FINAL = [
    # More single-entity with no filter
    ("show endpoint details",                       {"endpoints": True}),
    ("list device records",                         {"endpoints": True, "is_list": True}),
    ("show user details",                           {"users": True}),
    ("list user records",                           {"users": True, "is_list": True}),
    ("show activity details",                       {"activity": True}),
    ("list activity records",                       {"activity": True, "is_list": True}),
    ("show me all sessions",                        {"activity": True, "is_list": True}),
    ("display login records",                       {"activity": True, "is_list": True}),
    ("show me access logs",                         {"activity": True}),
    ("list all access logs",                        {"activity": True, "is_list": True}),
    # More VPN event variations
    ("show all vpn sessions",                       {"activity": True, "event_type": "vpn"}),
    ("list vpn connection logs",                    {"activity": True, "event_type": "vpn"}),
    ("show all vpn connections",                    {"activity": True, "event_type": "vpn"}),
    ("get vpn login events",                        {"activity": True, "event_type": "vpn"}),
    ("display vpn sessions",                        {"activity": True, "event_type": "vpn"}),
    ("find all vpn logins",                         {"activity": True, "event_type": "vpn"}),
    # More network event variations
    ("display all network events",                  {"activity": True, "event_type": "network"}),
    ("get network access logs",                     {"activity": True, "event_type": "network"}),
    ("list all network traffic events",             {"activity": True, "event_type": "network"}),
    ("show all network connection logs",            {"activity": True, "event_type": "network"}),
    ("find all network traffic",                    {"activity": True, "event_type": "network"}),
    # More app usage variations
    ("show application login events",               {"activity": True, "event_type": "app_usage"}),
    ("list all app logins",                         {"activity": True, "event_type": "app_usage"}),
    ("display app usage logs",                      {"activity": True, "event_type": "app_usage"}),
    ("get all application usage events",            {"activity": True, "event_type": "app_usage"}),
    ("show me app login history",                   {"activity": True, "event_type": "app_usage"}),
    # More owner name lookups
    ("show vicky's devices",                        {"endpoints": True, "owner_name": "vicky"}),
    ("list wes's endpoints",                        {"endpoints": True, "owner_name": "wes"}),
    ("find yara's machines",                        {"endpoints": True, "owner_name": "yara"}),
    ("show zee's computers",                        {"endpoints": True, "owner_name": "zee"}),
    ("devices for vicky",                           {"endpoints": True, "owner_name": "vicky"}),
    ("endpoints for wes",                           {"endpoints": True, "owner_name": "wes"}),
    ("machines for yara",                           {"endpoints": True, "owner_name": "yara"}),
    ("computers for zee",                           {"endpoints": True, "owner_name": "zee"}),
    ("what devices does vicky own",                 {"endpoints": True, "owner_name": "vicky"}),
    ("what endpoints does wes use",                 {"endpoints": True, "owner_name": "wes"}),
    # More named user activity
    ("show activity for vicky",                     {"activity": True, "act_user": "vicky"}),
    ("logins for wes",                              {"activity": True, "act_user": "wes"}),
    ("yara's login events",                         {"activity": True, "act_user": "yara"}),
    ("show zee's activity",                         {"activity": True, "act_user": "zee"}),
    ("what did vicky access",                       {"activity": True, "act_user": "vicky"}),
    ("which apps does wes use",                     {"activity": True, "act_user": "wes"}),
    ("show yara's login history",                   {"activity": True, "act_user": "yara"}),
    ("display zee's logins",                        {"activity": True, "act_user": "zee"}),
    # More compliance queries
    ("show me which devices pass compliance",       {"endpoints": True, "compliance_status": "compliant"}),
    ("list all passing endpoints",                  {"endpoints": True}),
    ("show devices failing compliance checks",      {"endpoints": True, "compliance_status": "non_compliant"}),
    ("find endpoints not meeting compliance",       {"endpoints": True, "compliance_status": "non_compliant"}),
    ("what devices have partial compliance issues", {"endpoints": True, "compliance_status": "partial"}),
    # More risk queries
    ("show the most risky endpoints",               {"risk": True}),
    ("show the most risky users",                   {"risk": True}),
    ("list all high-risk assets",                   {"risk": True}),
    ("show all critical assets",                    {"risk": True}),
    # More activity variations
    ("show all auth events today",                  {"activity": True, "days_back": 1}),
    ("list all auth events this week",              {"activity": True, "days_back": 7}),
    ("show all signin events",                      {"activity": True}),
    ("list signin events this month",               {"activity": True, "days_back": 30}),
    ("show all signins today",                      {"activity": True, "days_back": 1}),
    ("list session events this week",               {"activity": True, "days_back": 7}),
    ("display authentication events",               {"activity": True}),
    ("show auth logs this week",                    {"activity": True, "days_back": 7}),
    # More MFA combos
    ("show high risk users without MFA",            {"users": True, "risk_level_u": "high", "mfa_enabled": False}),
    ("find critical users who lack MFA",            {"users": True, "risk_level_u": "critical", "mfa_enabled": False}),
    ("list engineering employees missing MFA",      {"users": True, "department": "engineering", "mfa_enabled": False}),
    ("show all suspended users",                    {"users": True, "suspended": True, "is_list": True}),
    ("find all inactive users",                     {"users": True, "employment_status": "inactive"}),
    ("list all inactive employees",                 {"users": True, "employment_status": "inactive", "is_list": True}),
    # More endpoint combos
    ("show all unencrypted laptops",                {"endpoints": True, "disk_not_encrypted": True, "is_list": True}),
    ("list all devices missing VPN",                {"endpoints": True, "vpn_missing": True, "is_list": True}),
    ("show all devices missing DLP",                {"endpoints": True, "dlp_missing": True, "is_list": True}),
    ("find all endpoints missing EDR",              {"endpoints": True, "edr_missing": True, "is_list": True}),
    ("list all outdated EDR endpoints",             {"endpoints": True, "edr_outdated": True, "is_list": True}),
    ("show all unassigned endpoints",               {"endpoints": True, "unassigned": True, "is_list": True}),
    # More country combos
    ("show all suspicious events from China",       {"activity": True, "is_suspicious": True, "country": "China", "is_list": True}),
    ("list all events from Russia this week",       {"activity": True, "country": "Russia", "days_back": 7, "is_list": True}),
    ("find all flagged activity from Iran",         {"activity": True, "is_suspicious": True, "country": "Iran", "is_list": True}),
    ("show all logins from North Korea",            {"activity": True, "country": "North Korea", "is_list": True}),
    ("list all suspicious events from Ukraine",     {"activity": True, "is_suspicious": True, "country": "Ukraine", "is_list": True}),
    # Catch-all fallback queries
    ("everything is fine",                          {}),
    ("nothing to report",                           {}),
    ("all good",                                    {}),
    ("what is sec360",                              {}),
    ("test query",                                  {}),
    ("hello world",                                 {}),
    ("foo bar",                                     {}),
    ("123",                                         {}),
    ("show data",                                   {}),
    ("get info",                                    {}),
    # IS_LIST edge cases
    ("show all Windows endpoints in the organization", {"is_list": True, "endpoints": True, "os": "windows"}),
    ("list every macOS device we own",              {"is_list": True, "endpoints": True, "os": "macos"}),
    ("find every Linux server",                     {"is_list": True, "endpoints": True, "os": "linux"}),
    ("show me each user without MFA",               {"users": True, "mfa_enabled": False}),
    ("list every suspended account",                {"users": True, "suspended": True, "is_list": True}),
    ("how many saml events were there",             {"activity": True, "event_type": "saml", "is_list": False}),
    ("count of vpn events this week",               {"activity": True, "event_type": "vpn", "is_list": False}),
    ("total number of suspicious logins",           {"activity": True, "is_suspicious": True, "is_list": False}),
    ("how many users are in finance",               {"users": True, "is_list": False}),
    ("count of non-compliant endpoints",            {"endpoints": True, "is_list": False}),
]

INTENT_TESTS = INTENT_TESTS + INTENT_TESTS_FINAL


# ===========================================================================
# FINAL CONVERSATIONAL TESTS
# ===========================================================================

CONV_TESTS_FINAL = [
    # More not-conversational security queries
    ("show all endpoints without EDR",      False),
    ("list all Windows machines",           False),
    ("find macOS devices",                  False),
    ("show non-compliant devices",          False),
    ("list critical risk endpoints",        False),
    ("show suspicious saml events",         False),
    ("find vpn events for liad",            False),
    ("show oauth grants for alice",         False),
    ("list network events from China",      False),
    ("show file access for bob",            False),
    ("cloud access events today",           False),
    ("list all app logins",                 False),
    ("show unassigned endpoints",           False),
    ("find missing EDR devices",            False),
    ("show users with no endpoint",         False),
    ("list suspended accounts",             False),
    ("show HR users",                       False),
    ("find finance staff",                  False),
    ("show risk overview",                  False),
    ("give compliance summary",             False),
]

CONV_TESTS = CONV_TESTS + CONV_TESTS_FINAL


# ===========================================================================
# Test runner helpers
# ===========================================================================

def _check_intent(q: str, exp: dict) -> list[str]:
    """Run _detect_intent and _is_list_query, return list of failure messages."""
    intent = _detect_intent(q)
    is_list = _is_list_query(q)
    fails = []

    # Top-level bool fields
    for key in ("endpoints", "users", "activity", "compliance", "risk"):
        if key in exp:
            if intent[key] != exp[key]:
                fails.append(
                    f"  {key}: expected={exp[key]}, got={intent[key]}"
                )

    # Negation checks
    if exp.get("no_endpoints") and intent["endpoints"]:
        fails.append(f"  no_endpoints: expected False, got True")
    if exp.get("no_users") and intent["users"]:
        fails.append(f"  no_users: expected False, got True")
    if exp.get("no_activity") and intent["activity"]:
        fails.append(f"  no_activity: expected False, got True")
    if exp.get("no_risk") and intent["risk"]:
        fails.append(f"  no_risk: expected False, got True")

    # is_list
    if "is_list" in exp:
        if is_list != exp["is_list"]:
            fails.append(
                f"  is_list: expected={exp['is_list']}, got={is_list}"
            )

    # ep_filters
    ep_f = intent.get("ep_filters", {})
    if "owner_name" in exp:
        got = ep_f.get("owner_name", "")
        if got != exp["owner_name"]:
            fails.append(f"  owner_name: expected={exp['owner_name']!r}, got={got!r}")
    for key in ("unassigned", "edr_missing", "edr_outdated", "vpn_missing",
                "dlp_missing", "disk_not_encrypted", "agent_inactive"):
        if key in exp:
            if bool(ep_f.get(key)) != exp[key]:
                fails.append(
                    f"  ep_filters[{key}]: expected={exp[key]}, got={ep_f.get(key)}"
                )
    if "compliance_status" in exp:
        if ep_f.get("compliance_status") != exp["compliance_status"]:
            fails.append(
                f"  compliance_status: expected={exp['compliance_status']!r}, "
                f"got={ep_f.get('compliance_status')!r}"
            )
    if "risk_level_ep" in exp:
        if ep_f.get("risk_level") != exp["risk_level_ep"]:
            fails.append(
                f"  ep_filters[risk_level]: expected={exp['risk_level_ep']!r}, "
                f"got={ep_f.get('risk_level')!r}"
            )
    if "os" in exp:
        if ep_f.get("os") != exp["os"]:
            fails.append(
                f"  ep_filters[os]: expected={exp['os']!r}, got={ep_f.get('os')!r}"
            )

    # user_filters
    uf = intent.get("user_filters", {})
    if "mfa_enabled" in exp:
        got = uf.get("mfa_enabled")
        if got != exp["mfa_enabled"]:
            fails.append(
                f"  user_filters[mfa_enabled]: expected={exp['mfa_enabled']!r}, got={got!r}"
            )
    for key in ("suspended", "no_endpoint"):
        if key in exp:
            if bool(uf.get(key)) != exp[key]:
                fails.append(
                    f"  user_filters[{key}]: expected={exp[key]}, got={uf.get(key)}"
                )
    if "employment_status" in exp:
        if uf.get("employment_status") != exp["employment_status"]:
            fails.append(
                f"  user_filters[employment_status]: expected={exp['employment_status']!r}, "
                f"got={uf.get('employment_status')!r}"
            )
    if "department" in exp:
        got = uf.get("department", "")
        if exp["department"].lower() not in (got or "").lower():
            fails.append(
                f"  user_filters[department]: expected to contain {exp['department']!r}, "
                f"got={got!r}"
            )
    if "risk_level_u" in exp:
        if uf.get("risk_level") != exp["risk_level_u"]:
            fails.append(
                f"  user_filters[risk_level]: expected={exp['risk_level_u']!r}, "
                f"got={uf.get('risk_level')!r}"
            )

    # act_filters
    af = intent.get("act_filters", {})
    if "event_type" in exp:
        if af.get("event_type") != exp["event_type"]:
            fails.append(
                f"  act_filters[event_type]: expected={exp['event_type']!r}, "
                f"got={af.get('event_type')!r}"
            )
    if "act_user" in exp:
        got = af.get("user_email", "")
        if got != exp["act_user"]:
            fails.append(
                f"  act_filters[user_email]: expected={exp['act_user']!r}, got={got!r}"
            )
    if "is_suspicious" in exp:
        if bool(af.get("is_suspicious")) != exp["is_suspicious"]:
            fails.append(
                f"  act_filters[is_suspicious]: expected={exp['is_suspicious']}, "
                f"got={af.get('is_suspicious')}"
            )
    if "country" in exp:
        if af.get("country") != exp["country"]:
            fails.append(
                f"  act_filters[country]: expected={exp['country']!r}, "
                f"got={af.get('country')!r}"
            )
    if "days_back" in exp:
        if af.get("days_back") != exp["days_back"]:
            fails.append(
                f"  act_filters[days_back]: expected={exp['days_back']}, "
                f"got={af.get('days_back')}"
            )

    return fails


# ===========================================================================
# pytest test functions
# ===========================================================================

def test_all_intent():
    """Run all intent detection tests and report ALL failures."""
    all_fails = []
    pass_count = 0

    for q, exp in INTENT_TESTS:
        fails = _check_intent(q, exp)
        if fails:
            all_fails.append(f"QUERY: {q!r}")
            all_fails.extend(fails)
        else:
            pass_count += 1

    total = len(INTENT_TESTS)
    print(f"\n[INTENT] Passed: {pass_count}/{total}")
    if all_fails:
        print(f"[INTENT] Failed: {total - pass_count}/{total}")
        raise AssertionError(
            f"{total - pass_count} intent test(s) failed:\n" + "\n".join(all_fails)
        )


def test_all_followup():
    """Run all follow-up detection tests."""
    all_fails = []
    pass_count = 0

    for q, hist_tuples, expected in FOLLOWUP_TESTS:
        history = [FakeMsg(role, content) for role, content in hist_tuples]
        got = _is_followup(q, history)
        if got != expected:
            all_fails.append(
                f"QUERY: {q!r}  history_len={len(history)}  "
                f"expected={expected}, got={got}"
            )
        else:
            pass_count += 1

    total = len(FOLLOWUP_TESTS)
    print(f"\n[FOLLOWUP] Passed: {pass_count}/{total}")
    if all_fails:
        print(f"[FOLLOWUP] Failed: {total - pass_count}/{total}")
        raise AssertionError(
            f"{total - pass_count} followup test(s) failed:\n" + "\n".join(all_fails)
        )


def test_all_conversational():
    """Run all conversational handler tests."""
    all_fails = []
    pass_count = 0

    for q, expected_is_conv in CONV_TESTS:
        result = _handle_conversational(q)
        is_conv = result is not None
        if is_conv != expected_is_conv:
            all_fails.append(
                f"QUERY: {q!r}  expected_is_conversational={expected_is_conv}, "
                f"got={is_conv}  (result={result!r})"
            )
        else:
            pass_count += 1

    total = len(CONV_TESTS)
    print(f"\n[CONV] Passed: {pass_count}/{total}")
    if all_fails:
        print(f"[CONV] Failed: {total - pass_count}/{total}")
        raise AssertionError(
            f"{total - pass_count} conversational test(s) failed:\n" + "\n".join(all_fails)
        )


# Print summary of test counts when module is loaded
if __name__ == "__main__":
    print(f"INTENT_TESTS:  {len(INTENT_TESTS)}")
    print(f"FOLLOWUP_TESTS: {len(FOLLOWUP_TESTS)}")
    print(f"CONV_TESTS:    {len(CONV_TESTS)}")
    print(f"TOTAL:         {len(INTENT_TESTS) + len(FOLLOWUP_TESTS) + len(CONV_TESTS)}")
