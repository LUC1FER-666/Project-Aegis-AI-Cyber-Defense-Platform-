"""
Auth dependencies for asset-discovery.
Validates JWT tokens by calling the shared aegis_common auth library.
Each service validates tokens locally — no round-trip to gateway needed.
"""
from typing import Annotated
import sys
sys.path.insert(0, "/shared/python")
from aegis_common.auth import TokenValidationError, decode_token
from aegis_common.models import UserRole
from app.config import get_settings
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

settings = get_settings()
_bearer = HTTPBearer(auto_error=True)


class TokenUser(BaseModel):
    user_id: str
    email: str
    role: UserRole


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
) -> TokenUser:
    try:
        payload = decode_token(
            credentials.credentials,
            settings.jwt_secret_key,
            settings.jwt_algorithm,
            expected_type="access",
        )
        return TokenUser(user_id=payload.sub, email=payload.email, role=payload.role)
    except TokenValidationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


CurrentUser = Annotated[TokenUser, Depends(get_current_user)]


def require_role(minimum_role: UserRole):
    async def _check(current_user: CurrentUser) -> None:
        hierarchy = [
            UserRole.READ_ONLY, UserRole.EXECUTIVE, UserRole.SOC_ANALYST,
            UserRole.THREAT_HUNTER, UserRole.SOC_LEAD, UserRole.ADMIN,
        ]
        if hierarchy.index(current_user.role) < hierarchy.index(minimum_role):
            raise HTTPException(status_code=403, detail=f"Requires {minimum_role.value}")
    return Depends(_check)


RequireSOCAnalyst = require_role(UserRole.SOC_ANALYST)
RequireSOCLead = require_role(UserRole.SOC_LEAD)
RequireAdmin = require_role(UserRole.ADMIN)
