"""
User management endpoints (admin only).
GET/POST/PATCH/DELETE /users
"""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.auth import hash_password
from aegis_common.logging import get_logger
from aegis_common.models import UserRole

from app.database import DBSession
from app.dependencies import CurrentUser, RequireAdmin, RequireSOCLead
from app.models.db import User
from app.models.schemas import UserCreate, UserListResponse, UserRead, UserUpdate

router = APIRouter(prefix="/users", tags=["User Management"])
logger = get_logger(__name__)


@router.get("", response_model=UserListResponse)
async def list_users(
    current_user: CurrentUser,
    _: Annotated[None, RequireSOCLead],
    db: DBSession,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    role: UserRole | None = None,
    is_active: bool | None = None,
) -> UserListResponse:
    """List all users. Requires SOC Lead or higher."""
    query = select(User)
    count_query = select(func.count(User.id))

    if role is not None:
        query = query.where(User.role == role.value)
        count_query = count_query.where(User.role == role.value)
    if is_active is not None:
        query = query.where(User.is_active == is_active)
        count_query = count_query.where(User.is_active == is_active)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    query = query.offset((page - 1) * page_size).limit(page_size).order_by(User.created_at.desc())
    result = await db.execute(query)
    users = result.scalars().all()

    return UserListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[UserRead.model_validate(u) for u in users],
    )


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    current_user: CurrentUser,
    _: Annotated[None, RequireAdmin],
    db: DBSession,
) -> UserRead:
    """Create a new user. Requires Admin."""
    # Check uniqueness
    existing = await db.execute(
        select(User).where((User.email == body.email) | (User.username == body.username))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username already exists",
        )

    user = User(
        email=body.email,
        username=body.username,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
        role=body.role.value,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()

    logger.info("user_created", created_by=str(current_user.id), new_user=body.email)
    return UserRead.model_validate(user)


@router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: uuid.UUID,
    current_user: CurrentUser,
    _: Annotated[None, RequireSOCLead],
    db: DBSession,
) -> UserRead:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    current_user: CurrentUser,
    _: Annotated[None, RequireAdmin],
    db: DBSession,
) -> UserRead:
    """Update user role or active status. Requires Admin."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent self-demotion
    if str(user.id) == str(current_user.id) and body.role is not None:
        if UserRole(body.role) != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot change your own role",
            )

    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        user.role = body.role.value
    if body.is_active is not None:
        user.is_active = body.is_active

    await db.flush()
    logger.info("user_updated", updated_by=str(current_user.id), target_user=str(user_id))
    return UserRead.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: uuid.UUID,
    current_user: CurrentUser,
    _: Annotated[None, RequireAdmin],
    db: DBSession,
) -> None:
    """Soft-delete (deactivate) a user. Requires Admin."""
    if str(user_id) == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.is_active = False
    await db.flush()
    logger.info("user_deactivated", deactivated_by=str(current_user.id), target=str(user_id))
