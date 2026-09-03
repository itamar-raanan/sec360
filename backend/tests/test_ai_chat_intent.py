"""
200-query intent-detection test suite for the AI chatbot.

Each test is a tuple:
  (query_string, expected_dict)

expected_dict keys (all optional — only checked if present):
  users          bool
  endpoints      bool
  activity       bool
  compliance     bool
  risk           bool
  mfa_enabled    bool | None        → user_filters["mfa_enabled"]
  unassigned     bool               → ep_filters["unassigned"]
  edr_missing    bool
  edr_outdated   bool
  wss_missing    bool
  dlp_missing    bool
  disk_not_encrypted bool
  compliance_status  str            → ep_filters["compliance_status"]
  agent_inactive bool
  no_endpoint    bool               → user_filters["no_endpoint"]
  suspended      bool               → user_filters["suspended"]
  employment_status str
  department     str (substring)
  risk_level_ep  str                → ep_filters["risk_level"]
  risk_level_u   str                → user_filters["risk_level"]
  country        str                → act_filters["country"]
  is_suspicious  bool               → act_filters["is_suspicious"]
  days_back      int                → act_filters["days_back"]
  os             str                → ep_filters["os"]
  is_list        bool               → _is_list_query()
  no_risk        bool               → intent["risk"] must be False
  no_users       bool               → intent["users"] must be False
  no_endpoints   bool               → intent["endpoints"] must be False
"""
import re
import sys
import textwrap

sys.path.insert(0, "/app")
from app.api.routes.ai_chat import _detect_intent, _is_list_query

# ── Test definitions ────────────────────────────────────────────────────────

TESTS = [
    # ─── ENDPOINT LISTING (no filter) ────────────────────────────────────────
    ("list all endpoints",                          {"endpoints": True, "is_list": True}),
    ("show me all devices",                         {"endpoints": True, "is_list": True}),
    ("give me all machines",                        {"endpoints": True, "is_list": True}),
    ("display all hosts",                           {"endpoints": True, "is_list": True}),
    ("fetch all computers",                         {"endpoints": True, "is_list": True}),
    ("what are all the workstations",               {"endpoints": True, "is_list": True}),
    ("show all laptops",                            {"endpoints": True, "is_list": True}),
    ("list all PCs",                                {"endpoints": True, "is_list": True}),

    # ─── UNASSIGNED ENDPOINTS ─────────────────────────────────────────────────
    ("list all endpoints without user assign",      {"endpoints": True, "unassigned": True,
                                                     "no_users": True, "is_list": True}),
    ("show endpoints with no owner",                {"endpoints": True, "unassigned": True,
                                                     "no_users": True, "is_list": True}),
    ("unassigned devices",                          {"endpoints": True, "unassigned": True}),
    ("endpoints not assigned to any user",          {"endpoints": True, "unassigned": True,
                                                     "no_users": True}),
    ("machines missing owner",                      {"endpoints": True, "unassigned": True}),
    ("devices without an assigned user",            {"endpoints": True, "unassigned": True,
                                                     "no_users": True}),
    ("endpoints with no assigned user",             {"endpoints": True, "unassigned": True,
                                                     "no_users": True}),
    ("show unassigned endpoints",                   {"endpoints": True, "unassigned": True,
                                                     "is_list": True}),

    # ─── EDR MISSING ─────────────────────────────────────────────────────────
    ("endpoints missing EDR",                       {"endpoints": True, "edr_missing": True}),
    ("devices without SentinelOne",                 {"endpoints": True, "edr_missing": True}),
    ("list hosts missing S1",                       {"endpoints": True, "edr_missing": True,
                                                     "is_list": True}),
    ("machines without EDR agent",                  {"endpoints": True, "edr_missing": True}),
    ("no SentinelOne installed",                    {"endpoints": True, "edr_missing": True}),
    ("endpoints lacking S1",                        {"endpoints": True, "edr_missing": True}),

    # ─── EDR OUTDATED ─────────────────────────────────────────────────────────
    ("endpoints with outdated S1 agent",            {"endpoints": True, "edr_outdated": True}),
    ("devices with outdated SentinelOne",           {"endpoints": True, "edr_outdated": True}),
    ("list outdated EDR endpoints",                 {"endpoints": True, "edr_outdated": True,
                                                     "is_list": True}),
    ("S1 agent not updated",                        {"endpoints": True, "edr_outdated": True}),
    ("machines with old SentinelOne version",       {"endpoints": True, "edr_outdated": True}),
    ("show me endpoints where S1 is out of date",   {"endpoints": True, "edr_outdated": True,
                                                     "is_list": True}),

    # ─── WSS MISSING ─────────────────────────────────────────────────────────
    ("endpoints without WSS",                       {"endpoints": True, "wss_missing": True}),
    ("devices missing Cloud SWG",                   {"endpoints": True, "wss_missing": True}),
    ("list machines with no WSS",                   {"endpoints": True, "wss_missing": True,
                                                     "is_list": True}),
    ("no WSS installed on endpoints",               {"endpoints": True, "wss_missing": True}),
    ("hosts without Symantec WSS agent",            {"endpoints": True, "wss_missing": True}),

    # ─── DLP MISSING ─────────────────────────────────────────────────────────
    ("endpoints without DLP",                       {"endpoints": True, "dlp_missing": True}),
    ("devices missing DLP agent",                   {"endpoints": True, "dlp_missing": True}),
    ("list hosts with no DLP",                      {"endpoints": True, "dlp_missing": True,
                                                     "is_list": True}),
    ("machines lacking DLP",                        {"endpoints": True, "dlp_missing": True}),

    # ─── DISK ENCRYPTION ─────────────────────────────────────────────────────
    ("endpoints without disk encryption",           {"endpoints": True, "disk_not_encrypted": True}),
    ("unencrypted devices",                         {"endpoints": True, "disk_not_encrypted": True}),
    ("list machines not encrypted",                 {"endpoints": True, "disk_not_encrypted": True,
                                                     "is_list": True}),
    ("no BitLocker endpoints",                      {"endpoints": True, "disk_not_encrypted": True}),
    ("devices without FileVault",                   {"endpoints": True, "disk_not_encrypted": True}),

    # ─── COMPLIANCE STATUS ───────────────────────────────────────────────────
    ("non-compliant endpoints",                     {"endpoints": True,
                                                     "compliance_status": "non_compliant"}),
    ("list non compliant devices",                  {"endpoints": True,
                                                     "compliance_status": "non_compliant",
                                                     "is_list": True}),
    ("show me failed compliance endpoints",         {"endpoints": True,
                                                     "compliance_status": "non_compliant",
                                                     "is_list": True}),
    ("partially compliant machines",                {"endpoints": True,
                                                     "compliance_status": "partial"}),
    ("list partial compliance endpoints",           {"endpoints": True,
                                                     "compliance_status": "partial",
                                                     "is_list": True}),
    ("fully compliant endpoints",                   {"endpoints": True,
                                                     "compliance_status": "compliant"}),

    # ─── OS FILTER ───────────────────────────────────────────────────────────
    ("show me all Windows endpoints",               {"endpoints": True, "os": "windows",
                                                     "is_list": True}),
    ("list macOS devices",                          {"endpoints": True, "os": "macos",
                                                     "is_list": True}),
    ("list Linux machines",                         {"endpoints": True, "os": "linux",
                                                     "is_list": True}),
    ("Windows laptops",                             {"endpoints": True, "os": "windows"}),
    ("Mac OS endpoints",                            {"endpoints": True, "os": "macos"}),

    # ─── ENDPOINT RISK ───────────────────────────────────────────────────────
    ("list high risk endpoints",                    {"endpoints": True, "risk_level_ep": "high",
                                                     "no_risk": True, "is_list": True}),
    ("critical risk devices",                       {"endpoints": True, "risk_level_ep": "critical",
                                                     "no_risk": True}),
    ("show me medium risk machines",                {"endpoints": True, "risk_level_ep": "medium",
                                                     "no_risk": True, "is_list": True}),
    ("low risk endpoints",                          {"endpoints": True, "risk_level_ep": "low",
                                                     "no_risk": True}),
    ("endpoints with high risk score",              {"endpoints": True, "risk_level_ep": "high",
                                                     "no_risk": True}),

    # ─── AGENT INACTIVE ──────────────────────────────────────────────────────
    ("endpoints with inactive agents",              {"endpoints": True, "agent_inactive": True}),
    ("devices with stopped agent",                  {"endpoints": True, "agent_inactive": True}),
    ("show inactive agent endpoints",               {"endpoints": True, "agent_inactive": True,
                                                     "is_list": True}),

    # ─── USER LISTING (no filter) ────────────────────────────────────────────
    ("list all users",                              {"users": True, "is_list": True}),
    ("show me all employees",                       {"users": True, "is_list": True}),
    ("give me all staff",                           {"users": True, "is_list": True}),
    ("display all accounts",                        {"users": True, "is_list": True}),
    ("who are all the workers",                     {"users": True, "is_list": True}),

    # ─── MFA ──────────────────────────────────────────────────────────────────
    ("users without MFA",                           {"users": True, "mfa_enabled": False,
                                                     "is_list": True}),
    ("employees with no two-factor",                {"users": True, "mfa_enabled": False}),
    ("staff missing MFA",                           {"users": True, "mfa_enabled": False}),
    ("accounts without 2FA",                        {"users": True, "mfa_enabled": False}),
    ("show users where MFA is disabled",            {"users": True, "mfa_enabled": False,
                                                     "is_list": True}),
    ("users with MFA enabled",                      {"users": True, "mfa_enabled": True,
                                                     "is_list": True}),
    ("employees who have 2FA",                      {"users": True, "mfa_enabled": True}),
    ("show users with MFA active",                  {"users": True, "mfa_enabled": True,
                                                     "is_list": True}),
    ("staff with two-factor authentication on",     {"users": True, "mfa_enabled": True}),
    ("accounts with MFA on",                        {"users": True, "mfa_enabled": True}),

    # ─── SUSPENDED ───────────────────────────────────────────────────────────
    ("suspended users",                             {"users": True, "suspended": True}),
    ("show me suspended accounts",                  {"users": True, "suspended": True,
                                                     "is_list": True}),
    ("locked out users",                            {"users": True, "suspended": True}),
    ("disabled accounts",                           {"users": True, "suspended": True}),
    ("blocked users",                               {"users": True, "suspended": True}),

    # ─── NO ENDPOINT ─────────────────────────────────────────────────────────
    ("users with no endpoint",                      {"users": True, "no_endpoint": True,
                                                     "no_endpoints": True}),
    ("employees without a device",                  {"users": True, "no_endpoint": True,
                                                     "no_endpoints": True}),
    ("staff missing endpoint",                      {"users": True, "no_endpoint": True}),
    ("who has no laptop",                           {"users": True, "no_endpoint": True}),
    ("people without a computer",                   {"users": True, "no_endpoint": True,
                                                     "no_endpoints": True}),
    ("show users with no machines",                 {"users": True, "no_endpoint": True,
                                                     "is_list": True}),
    ("accounts with no devices",                    {"users": True, "no_endpoint": True}),

    # ─── USER RISK ────────────────────────────────────────────────────────────
    ("show me users with high risk score",          {"users": True, "risk_level_u": "high",
                                                     "no_risk": True, "is_list": True}),
    ("list high risk users",                        {"users": True, "risk_level_u": "high",
                                                     "no_risk": True, "is_list": True}),
    ("critical risk employees",                     {"users": True, "risk_level_u": "critical",
                                                     "no_risk": True}),
    ("medium risk staff",                           {"users": True, "risk_level_u": "medium",
                                                     "no_risk": True}),
    ("low risk users",                              {"users": True, "risk_level_u": "low",
                                                     "no_risk": True}),
    ("users with critical risk score",              {"users": True, "risk_level_u": "critical",
                                                     "no_risk": True}),
    ("high risk accounts",                          {"users": True, "risk_level_u": "high",
                                                     "no_risk": True}),
    ("show me employees with high risk",            {"users": True, "risk_level_u": "high",
                                                     "no_risk": True, "is_list": True}),

    # ─── DEPARTMENT ───────────────────────────────────────────────────────────
    ("users in engineering",                        {"users": True, "department": "engineering"}),
    ("employees in finance department",             {"users": True, "department": "finance"}),
    ("staff in HR",                                 {"users": True}),  # HR too short, but users should be set
    ("people in the sales team",                    {"users": True, "department": "sales"}),
    ("users in marketing",                          {"users": True, "department": "marketing"}),
    ("show me R&D department employees",            {"users": True}),
    ("list users in the legal team",                {"users": True, "department": "legal",
                                                     "is_list": True}),

    # ─── INACTIVE USERS ──────────────────────────────────────────────────────
    ("inactive users",                              {"users": True, "employment_status": "inactive"}),
    ("show me inactive employees",                  {"users": True, "employment_status": "inactive",
                                                     "is_list": True}),
    ("not active accounts",                         {"users": True, "employment_status": "inactive"}),

    # ─── ACTIVITY: GENERAL ───────────────────────────────────────────────────
    ("show recent login events",                    {"activity": True, "is_list": True}),
    ("list all activity",                           {"activity": True, "is_list": True}),
    ("show access events",                          {"activity": True, "is_list": True}),
    ("recent auth events",                          {"activity": True}),
    ("show SAML login events",                      {"activity": True, "is_list": True}),
    ("list OAuth sessions",                         {"activity": True, "is_list": True}),

    # ─── ACTIVITY: SUSPICIOUS ────────────────────────────────────────────────
    ("suspicious login events",                     {"activity": True, "is_suspicious": True,
                                                     "no_users": True}),
    ("show me suspicious activity",                 {"activity": True, "is_suspicious": True,
                                                     "is_list": True}),
    ("flagged events",                              {"activity": True, "is_suspicious": True}),
    ("anomalous login activity",                    {"activity": True, "is_suspicious": True}),
    ("malicious access events",                     {"activity": True, "is_suspicious": True}),
    ("unusual auth events",                         {"activity": True, "is_suspicious": True}),
    ("threat activity",                             {"activity": True, "is_suspicious": True}),

    # ─── ACTIVITY: COUNTRY ───────────────────────────────────────────────────
    ("activity from Russia",                        {"activity": True, "country": "Russia",
                                                     "no_users": True}),
    ("login from China",                            {"activity": True, "country": "China",
                                                     "no_users": True}),
    ("show logins from Iran",                       {"activity": True, "country": "Iran",
                                                     "is_list": True}),
    ("activity from North Korea",                   {"activity": True, "country": "North Korea"}),
    ("access events from Germany",                  {"activity": True, "country": "Germany",
                                                     "no_users": True}),
    ("login from Ukraine",                          {"activity": True, "country": "Ukraine"}),
    ("events from Israel",                          {"activity": True, "country": "Israel"}),
    ("logins from USA",                             {"activity": True, "country": "United States"}),
    ("activity from United Kingdom",                {"activity": True, "country": "United Kingdom"}),
    ("signed in from India",                        {"activity": True, "country": "India",
                                                     "no_users": True}),

    # ─── ACTIVITY: TIME RANGE ────────────────────────────────────────────────
    ("login events today",                          {"activity": True, "days_back": 1}),
    ("activity last 24 hours",                      {"activity": True, "days_back": 1}),
    ("show events this week",                       {"activity": True, "days_back": 7}),
    ("activity last 7 days",                        {"activity": True, "days_back": 7}),
    ("logins this month",                           {"activity": True, "days_back": 30}),
    ("events last 30 days",                         {"activity": True, "days_back": 30}),
    ("activity last 14 days",                       {"activity": True, "days_back": 14}),
    ("login events last 3 days",                    {"activity": True, "days_back": 3}),

    # ─── COMPLIANCE SUMMARY ──────────────────────────────────────────────────
    ("what is the compliance status",               {"compliance": True}),
    ("show me compliance overview",                 {"compliance": True}),
    ("compliance summary",                          {"compliance": True}),
    ("compliance posture",                          {"compliance": True}),
    ("give me a compliance report",                 {"compliance": True}),
    ("how is our compliance",                       {"compliance": True}),
    ("security policy status",                      {"compliance": True}),
    ("endpoint compliance",                         {"compliance": True}),

    # ─── RISK DISTRIBUTION (generic) ─────────────────────────────────────────
    ("show me risk distribution",                   {"risk": True, "no_users": True,
                                                     "no_endpoints": True}),
    ("risk overview",                               {"risk": True}),
    ("risk summary",                                {"risk": True}),
    ("what is the overall risk",                    {"risk": True}),
    ("risky endpoints and users",                   {"risk": True}),
    ("show high risk overview",                     {"risk": True}),
    ("give me risk breakdown",                      {"risk": True}),

    # ─── ANALYSIS (LLM path — is_list should be False) ───────────────────────
    ("how many users have no MFA",                  {"users": True, "mfa_enabled": False,
                                                     "is_list": False}),
    ("what percentage of endpoints are compliant",  {"compliance": True, "is_list": False}),
    ("how many high risk users are there",          {"users": True, "risk_level_u": "high",
                                                     "no_risk": True, "is_list": False}),
    ("how many endpoints are non-compliant",        {"endpoints": True,
                                                     "compliance_status": "non_compliant",
                                                     "is_list": False}),
    ("count of suspended users",                    {"users": True, "suspended": True,
                                                     "is_list": False}),
    ("how many devices are missing EDR",            {"endpoints": True, "edr_missing": True,
                                                     "is_list": False}),
    ("total unencrypted endpoints",                 {"endpoints": True,
                                                     "disk_not_encrypted": True}),
    ("how many users are in engineering",           {"users": True, "department": "engineering",
                                                     "is_list": False}),
    ("percentage of users without 2FA",             {"users": True, "mfa_enabled": False,
                                                     "is_list": False}),
    ("summary of security posture",                 {"compliance": True, "is_list": False}),
    ("overview of endpoint health",                 {}),  # should return something meaningful
    ("status of EDR deployment",                    {}),
    ("compare compliant vs non-compliant",          {"compliance": True, "is_list": False}),
    ("average risk score",                          {}),
    ("trend in suspicious activity",                {"activity": True, "is_suspicious": True}),

    # ─── EDGE CASES / TRICKY ─────────────────────────────────────────────────
    # "without" must NOT match "with" MFA
    ("users without MFA should not match with",     {"users": True, "mfa_enabled": False}),
    # "non-compliant" must NOT set generic compliance=True
    ("non-compliant devices list",                  {"endpoints": True,
                                                     "compliance_status": "non_compliant",
                                                     "compliance": False}),
    # "partially compliant" must NOT set generic compliance
    ("partially compliant endpoints",               {"endpoints": True,
                                                     "compliance_status": "partial",
                                                     "compliance": False}),
    # Country in activity must NOT leak to department
    ("logins from Russia this week",                {"activity": True, "country": "Russia",
                                                     "no_users": True, "days_back": 7}),
    ("activity from Germany last 30 days",          {"activity": True, "country": "Germany",
                                                     "no_users": True, "days_back": 30}),
    # "login" contains "in" — must NOT set department
    ("suspicious login events today",               {"activity": True, "is_suspicious": True,
                                                     "no_users": True, "days_back": 1}),
    # High risk with entity → no generic risk
    ("high risk users",                             {"users": True, "risk_level_u": "high",
                                                     "no_risk": True}),
    ("critical risk endpoints",                     {"endpoints": True, "risk_level_ep": "critical",
                                                     "no_risk": True}),
    # Risk score phrasing variants
    ("users with a high risk score",                {"users": True, "risk_level_u": "high",
                                                     "no_risk": True}),
    ("endpoints with critical risk score",          {"endpoints": True, "risk_level_ep": "critical",
                                                     "no_risk": True}),
    # "assign" variants
    ("endpoints not assigned to a user",            {"endpoints": True, "unassigned": True}),
    ("devices with no user assigned",               {"endpoints": True, "unassigned": True}),
    ("hosts without owner",                         {"endpoints": True, "unassigned": True}),
    # Mixed entity — should not double-count
    ("endpoints without user",                      {"endpoints": True}),
    ("which users have suspended accounts",         {"users": True, "suspended": True,
                                                     "is_list": True}),
    # WSS variants
    ("machines without Symantec WSS",               {"endpoints": True, "wss_missing": True}),
    ("no WSS on these devices",                     {"endpoints": True, "wss_missing": True}),
    # Multiple filters combined
    ("high risk Windows endpoints",                 {"endpoints": True, "risk_level_ep": "high",
                                                     "os": "windows"}),
    ("critical risk macOS devices",                 {"endpoints": True, "risk_level_ep": "critical",
                                                     "os": "macos"}),
    # Activity + suspicious + country
    ("suspicious logins from China",                {"activity": True, "is_suspicious": True,
                                                     "country": "China"}),
    ("anomalous activity from Russia",              {"activity": True, "is_suspicious": True,
                                                     "country": "Russia"}),
    # Negations
    ("endpoints that are not encrypted",            {"endpoints": True,
                                                     "disk_not_encrypted": True}),
    ("users that are not suspended",                {"users": True}),
    # Short / ambiguous
    ("all users",                                   {"users": True, "is_list": True}),
    ("all endpoints",                               {"endpoints": True, "is_list": True}),
    ("all activity",                                {"activity": True, "is_list": True}),
    # Compound queries
    ("show me endpoints without EDR and without VPN", {"endpoints": True, "edr_missing": True}),
    ("users without MFA who are suspended",         {"users": True, "mfa_enabled": False,
                                                     "suspended": True}),
    # Natural questions
    ("who are the high risk users",                 {"users": True, "risk_level_u": "high",
                                                     "no_risk": True, "is_list": True}),
    ("which devices have no EDR",                   {"endpoints": True, "edr_missing": True,
                                                     "is_list": True}),
    ("find endpoints missing SentinelOne",          {"endpoints": True, "edr_missing": True}),
    ("get me the list of non-compliant endpoints",  {"endpoints": True,
                                                     "compliance_status": "non_compliant",
                                                     "is_list": True}),
    ("show all devices without disk encryption",    {"endpoints": True,
                                                     "disk_not_encrypted": True,
                                                     "is_list": True}),
    ("what endpoints have outdated agents",         {"endpoints": True, "edr_outdated": True}),
    ("which users don't have MFA",                  {"users": True, "mfa_enabled": False,
                                                     "is_list": True}),
    ("find users with no laptop",                   {"users": True, "no_endpoint": True}),
    ("show me everyone in finance",                 {"users": True, "department": "finance",
                                                     "is_list": True}),
    ("list all login events from Iran",             {"activity": True, "country": "Iran",
                                                     "is_list": True}),
    ("any suspicious logins today",                 {"activity": True, "is_suspicious": True,
                                                     "days_back": 1}),
    ("endpoint compliance breakdown",               {"compliance": True}),
    ("how many endpoints lack encryption",          {"endpoints": True,
                                                     "disk_not_encrypted": True}),
    ("critical risk users without MFA",             {"users": True, "risk_level_u": "critical",
                                                     "mfa_enabled": False, "no_risk": True}),
    ("show high risk users without 2FA",            {"users": True, "risk_level_u": "high",
                                                     "mfa_enabled": False, "no_risk": True,
                                                     "is_list": True}),
    ("list macOS endpoints with no EDR",            {"endpoints": True, "os": "macos",
                                                     "edr_missing": True, "is_list": True}),
    ("Windows devices without disk encryption",     {"endpoints": True, "os": "windows",
                                                     "disk_not_encrypted": True}),
]

# ── Runner ───────────────────────────────────────────────────────────────────

def check(query: str, expected: dict) -> tuple[bool, list[str]]:
    intent = _detect_intent(query)
    is_list = _is_list_query(query)
    ef = intent["ep_filters"]
    uf = intent["user_filters"]
    af = intent["act_filters"]

    failures = []

    def expect_true(key, val, label):
        if val and not intent.get(key):
            failures.append(f"expected {label}=True, got False")
        if val is False and intent.get(key):
            failures.append(f"expected {label}=False, got True")

    # Top-level intent booleans
    for k in ("endpoints", "users", "activity", "compliance", "risk"):
        if k in expected:
            expect_true(k, expected[k], k)

    # no_* shortcuts
    if expected.get("no_risk") and intent.get("risk"):
        failures.append("expected risk=False (no generic risk), got True")
    if expected.get("no_users") and intent.get("users"):
        failures.append("expected users=False, got True")
    if expected.get("no_endpoints") and intent.get("endpoints"):
        failures.append("expected endpoints=False, got True")

    # ep_filters
    if "unassigned"       in expected and bool(ef.get("unassigned"))       != bool(expected["unassigned"]):
        failures.append(f"unassigned: expected {expected['unassigned']}, got {ef.get('unassigned')}")
    if "edr_missing"      in expected and bool(ef.get("edr_missing"))      != bool(expected["edr_missing"]):
        failures.append(f"edr_missing: expected {expected['edr_missing']}, got {ef.get('edr_missing')}")
    if "edr_outdated"     in expected and bool(ef.get("edr_outdated"))     != bool(expected["edr_outdated"]):
        failures.append(f"edr_outdated: expected {expected['edr_outdated']}, got {ef.get('edr_outdated')}")
    if "wss_missing"      in expected and bool(ef.get("wss_missing"))      != bool(expected["wss_missing"]):
        failures.append(f"wss_missing: expected {expected['wss_missing']}, got {ef.get('wss_missing')}")
    if "dlp_missing"      in expected and bool(ef.get("dlp_missing"))      != bool(expected["dlp_missing"]):
        failures.append(f"dlp_missing: expected {expected['dlp_missing']}, got {ef.get('dlp_missing')}")
    if "disk_not_encrypted" in expected and bool(ef.get("disk_not_encrypted")) != bool(expected["disk_not_encrypted"]):
        failures.append(f"disk_not_encrypted: expected {expected['disk_not_encrypted']}, got {ef.get('disk_not_encrypted')}")
    if "agent_inactive"   in expected and bool(ef.get("agent_inactive"))   != bool(expected["agent_inactive"]):
        failures.append(f"agent_inactive: expected {expected['agent_inactive']}, got {ef.get('agent_inactive')}")
    if "compliance_status" in expected:
        if expected["compliance_status"] is False and ef.get("compliance_status"):
            failures.append(f"compliance_status: expected None, got {ef.get('compliance_status')}")
        elif expected["compliance_status"] and ef.get("compliance_status") != expected["compliance_status"]:
            failures.append(f"compliance_status: expected {expected['compliance_status']!r}, got {ef.get('compliance_status')!r}")
    if "risk_level_ep" in expected and ef.get("risk_level") != expected["risk_level_ep"]:
        failures.append(f"ep risk_level: expected {expected['risk_level_ep']!r}, got {ef.get('risk_level')!r}")
    if "os" in expected and ef.get("os") != expected["os"]:
        failures.append(f"os: expected {expected['os']!r}, got {ef.get('os')!r}")

    # user_filters
    if "mfa_enabled" in expected:
        if expected["mfa_enabled"] is False and uf.get("mfa_enabled") is not False:
            failures.append(f"mfa_enabled: expected False, got {uf.get('mfa_enabled')!r}")
        elif expected["mfa_enabled"] is True and uf.get("mfa_enabled") is not True:
            failures.append(f"mfa_enabled: expected True, got {uf.get('mfa_enabled')!r}")
    if "no_endpoint" in expected and bool(uf.get("no_endpoint")) != bool(expected["no_endpoint"]):
        failures.append(f"no_endpoint: expected {expected['no_endpoint']}, got {uf.get('no_endpoint')}")
    if "suspended"    in expected and bool(uf.get("suspended")) != bool(expected["suspended"]):
        failures.append(f"suspended: expected {expected['suspended']}, got {uf.get('suspended')}")
    if "employment_status" in expected and uf.get("employment_status") != expected["employment_status"]:
        failures.append(f"employment_status: expected {expected['employment_status']!r}, got {uf.get('employment_status')!r}")
    if "risk_level_u" in expected and uf.get("risk_level") != expected["risk_level_u"]:
        failures.append(f"user risk_level: expected {expected['risk_level_u']!r}, got {uf.get('risk_level')!r}")
    if "department" in expected:
        dept = uf.get("department", "")
        if expected["department"] not in (dept or ""):
            failures.append(f"department: expected substring {expected['department']!r}, got {dept!r}")

    # act_filters
    if "country"      in expected and af.get("country") != expected["country"]:
        failures.append(f"country: expected {expected['country']!r}, got {af.get('country')!r}")
    if "is_suspicious" in expected:
        if expected["is_suspicious"] and not af.get("is_suspicious"):
            failures.append(f"is_suspicious: expected True, got {af.get('is_suspicious')!r}")
        if expected["is_suspicious"] is False and af.get("is_suspicious"):
            failures.append(f"is_suspicious: expected False, got True")
    if "days_back"    in expected and af.get("days_back") != expected["days_back"]:
        failures.append(f"days_back: expected {expected['days_back']}, got {af.get('days_back')!r}")

    # is_list
    if "is_list" in expected and is_list != expected["is_list"]:
        failures.append(f"is_list: expected {expected['is_list']}, got {is_list}")

    return len(failures) == 0, failures


def run_all():
    passed = failed = 0
    fail_details = []

    for i, (query, expected) in enumerate(TESTS, 1):
        ok, errs = check(query, expected)
        if ok:
            passed += 1
        else:
            failed += 1
            fail_details.append((i, query, errs))

    total = passed + failed
    print(f"\n{'='*65}")
    print(f"  AI Chat Intent Tests  —  {total} queries")
    print(f"{'='*65}")
    print(f"  ✅ Passed: {passed}/{total}")
    print(f"  ❌ Failed: {failed}/{total}")
    print(f"{'='*65}\n")

    if fail_details:
        print("FAILURES:\n")
        for idx, q, errs in fail_details:
            print(f"  [{idx:03d}] {q!r}")
            for e in errs:
                print(f"         → {e}")
        print()

    return fail_details


if __name__ == "__main__":
    failures = run_all()
    sys.exit(1 if failures else 0)
