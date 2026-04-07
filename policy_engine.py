from datetime import datetime
import random

POLICIES = [
    {
        "id": "POL001",
        "name": "Working Hours Access",
        "description": "Block access outside working hours for standard users",
        "condition": lambda req: req["role"] == "standard" and not (9 <= req["hour"] <= 18),
        "action": "DENY",
        "reason": "Access outside working hours requires elevated privileges"
    },
    {
        "id": "POL002", 
"name": "Untrusted Device Block",
        "description": "Block access from unmanaged or untrusted devices",
        "condition": lambda req: req["device_trust"] == "untrusted",
        "action": "DENY",
        "reason": "Unmanaged devices are not permitted to access company resources"
    },
    {
        "id": "POL003",
        "name": "High Risk Location MFA",
        "description": "Require MFA for access from high risk countries",
        "condition": lambda req: req["location_risk"] == "high" and not req["mfa_verified"],
        "action": "DENY",
        "reason": "High risk location requires multi-factor authentication"
    },
    {
        "id": "POL004",
        "name": "Admin Privileged Access",
        "description": "Require MFA for all admin access regardless of location",
        "condition": lambda req: req["role"] == "admin" and not req["mfa_verified"],
        "action": "DENY",
        "reason": "Admin access always requires MFA verification"
    },
    {
        "id": "POL005",
        "name": "Sensitive Resource Protection",
        "description": "Only admins can access sensitive resources",
        "condition": lambda req: req["resource_sensitivity"] == "critical" and req["role"] != "admin",
        "action": "DENY",
        "reason": "Critical resources restricted to admin role only"
    },
    {
        "id": "POL006",
        "name": "Failed Login Lockout",
        "description": "Block users with too many failed login attempts",
        "condition": lambda req: req["failed_attempts"] >= 3,
        "action": "DENY",
        "reason": "Account locked due to multiple failed authentication attempts"
    },
    {
        "id": "POL007",
        "name": "VPN Required for Remote",
        "description": "Remote access requires VPN connection",
        "condition": lambda req: req["location"] == "remote" and not req["vpn_connected"],
        "action": "DENY",
        "reason": "Remote access requires active VPN connection"
    },
    {
        "id": "POL008",
        "name": "Step-Up Auth for Finance",
        "description": "Finance resources require step-up authentication",
        "condition": lambda req: req["resource_type"] == "finance" and req["auth_level"] < 2,
        "action": "ESCALATE",
        "reason": "Finance resources require step-up authentication — redirecting to MFA"
    },
]

def evaluate_request(request_data):
    triggered_policies = []
    final_action = "ALLOW"
    final_reason = "All zero trust policies passed — access granted"

    for policy in POLICIES:
        try:
            if policy["condition"](request_data):
                triggered_policies.append({
                    "id": policy["id"],
                    "name": policy["name"],
                    "action": policy["action"],
                    "reason": policy["reason"]
                })
                if policy["action"] == "DENY":
                    final_action = "DENY"
                elif policy["action"] == "ESCALATE" and final_action != "DENY":
                    final_action = "ESCALATE"
        except Exception as e:
            print(f"Policy {policy['id']} error: {e}")

    if not triggered_policies:
        final_reason = "All zero trust policies passed — access granted"
    elif final_action == "DENY":
        final_reason = triggered_policies[-1]["reason"]
    elif final_action == "ESCALATE":
        final_reason = triggered_policies[-1]["reason"]

    risk_score = calculate_risk_score(request_data)

    return {
        "action": final_action,
        "reason": final_reason,
        "triggered_policies": triggered_policies,
        "risk_score": risk_score,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "request": request_data
    }

def calculate_risk_score(req):
    score = 0
    if req.get("location_risk") == "high":
        score += 30
    elif req.get("location_risk") == "medium":
        score += 15
    if req.get("device_trust") == "untrusted":
        score += 25
    elif req.get("device_trust") == "partial":
        score += 10
    if not req.get("mfa_verified"):
        score += 20
    if req.get("failed_attempts", 0) > 0:
        score += req["failed_attempts"] * 10
    if req.get("resource_sensitivity") == "critical":
        score += 15
    if req.get("location") == "remote" and not req.get("vpn_connected"):
        score += 20
    hour = req.get("hour", 12)
    if not (9 <= hour <= 18):
        score += 10
    return min(score, 100)

def calculate_blast_radius(request_data, action):
    if action == "ALLOW":
        sensitivity = request_data.get("resource_sensitivity", "low")
        role = request_data.get("role", "standard")
        location_risk = request_data.get("location_risk", "low")

        affected_systems = []
        if sensitivity == "critical":
            affected_systems = ["Database Server", "File Storage", "Email System", "HR System", "Finance System", "Customer Data", "Source Code", "Admin Panel"]
        elif sensitivity == "high":
            affected_systems = ["File Storage", "Email System", "HR System", "Finance System"]
        else:
            affected_systems = ["File Storage", "Email System"]

        if role == "admin":
            affected_systems += ["Active Directory", "Cloud Infrastructure", "All Internal Systems"]

        data_at_risk = len(affected_systems) * 1000
        breach_cost = len(affected_systems) * 50000

        return {
            "affected_systems": affected_systems,
            "data_records_at_risk": data_at_risk,
            "estimated_breach_cost": breach_cost,
            "severity": "CRITICAL" if len(affected_systems) > 6 else "HIGH" if len(affected_systems) > 3 else "MEDIUM"
        }
    return None

def generate_simulation_scenarios():
    scenarios = [
        {
            "name": "Normal Employee Access",
            "user": "john.smith@company.com",
            "role": "standard",
            "location": "office",
            "location_risk": "low",
            "device_trust": "trusted",
            "mfa_verified": True,
            "vpn_connected": True,
            "resource_sensitivity": "medium",
            "resource_type": "general",
            "auth_level": 2,
            "failed_attempts": 0,
            "hour": 10
        },
        {
            "name": "After Hours Access Attempt",
            "user": "jane.doe@company.com",
            "role": "standard",
            "location": "remote",
            "location_risk": "low",
            "device_trust": "trusted",
            "mfa_verified": True,
            "vpn_connected": True,
            "resource_sensitivity": "medium",
            "resource_type": "general",
            "auth_level": 2,
            "failed_attempts": 0,
            "hour": 23
        },
        {
            "name": "Compromised Account — Multiple Failed Logins",
            "user": "bob.jones@company.com",
            "role": "standard",
            "location": "remote",
            "location_risk": "high",
            "device_trust": "untrusted",
            "mfa_verified": False,
            "vpn_connected": False,
            "resource_sensitivity": "critical",
            "resource_type": "finance",
            "auth_level": 0,
            "failed_attempts": 5,
            "hour": 3
        },
        {
            "name": "Admin Access Without MFA",
            "user": "admin@company.com",
            "role": "admin",
            "location": "office",
            "location_risk": "low",
            "device_trust": "trusted",
            "mfa_verified": False,
            "vpn_connected": True,
            "resource_sensitivity": "critical",
            "resource_type": "admin",
            "auth_level": 1,
            "failed_attempts": 0,
            "hour": 14
        },
        {
            "name": "Remote Worker — High Risk Country",
            "user": "alice.wong@company.com",
            "role": "standard",
            "location": "remote",
            "location_risk": "high",
            "device_trust": "trusted",
            "mfa_verified": False,
            "vpn_connected": True,
            "resource_sensitivity": "low",
            "resource_type": "general",
            "auth_level": 1,
            "failed_attempts": 0,
            "hour": 11
        },
    ]
    return scenarios