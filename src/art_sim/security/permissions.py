"""Central role-to-permission policy and complete-mediation helper."""

from __future__ import annotations

from enum import StrEnum

from art_sim.domain.exceptions import AuthorizationError
from art_sim.security.identity import ApiRole, Identity


class Permission(StrEnum):
    """Explicit capabilities enforced at the HTTP boundary."""

    SIMULATION_READ = "simulation:read"
    SIMULATION_CREATE = "simulation:create"
    SIMULATION_APPROVE = "simulation:approve"
    SIMULATION_REJECT = "simulation:reject"
    SIMULATION_CANCEL = "simulation:cancel"
    SIMULATION_ADMIN = "simulation:admin"
    RISK_READ = "risk:read"
    ATTACK_PATH_READ = "attack_path:read"
    BLAST_RADIUS_READ = "blast_radius:read"
    REMEDIATION_READ = "remediation:read"
    VERIFICATION_READ = "verification:read"
    REPORT_READ = "report:read"
    AUDIT_READ = "audit:read"
    SECURITY_ADMIN = "security:admin"
    IDENTITY_ADMIN = "identity:admin"


_VIEWER = frozenset(
    {
        Permission.SIMULATION_READ,
        Permission.RISK_READ,
        Permission.ATTACK_PATH_READ,
        Permission.BLAST_RADIUS_READ,
        Permission.REMEDIATION_READ,
        Permission.VERIFICATION_READ,
        Permission.REPORT_READ,
    }
)
_OPERATOR = _VIEWER | frozenset(
    {
        Permission.SIMULATION_CREATE,
        Permission.SIMULATION_APPROVE,
        Permission.SIMULATION_REJECT,
        Permission.SIMULATION_CANCEL,
    }
)
ROLE_PERMISSIONS: dict[ApiRole, frozenset[Permission]] = {
    ApiRole.VIEWER: _VIEWER,
    ApiRole.OPERATOR: _OPERATOR,
    ApiRole.ADMIN: _OPERATOR
    | frozenset(
        {
            Permission.SIMULATION_ADMIN,
            Permission.AUDIT_READ,
            Permission.SECURITY_ADMIN,
            Permission.IDENTITY_ADMIN,
        }
    ),
}


def permissions_for_roles(roles: frozenset[ApiRole]) -> frozenset[str]:
    """Derive capabilities exclusively from the local policy, never token claims."""
    return frozenset(permission.value for role in roles for permission in ROLE_PERMISSIONS[role])


def authorize(identity: Identity, permission: Permission) -> None:
    """Fail closed unless the verified identity has the requested capability."""
    if permission.value not in identity.permissions:
        raise AuthorizationError("Identity does not have the required permission")
