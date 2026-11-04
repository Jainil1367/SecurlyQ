from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import admin_only
from app.db.session import get_db
from app.models import User
from app.schemas.user import RoleUpdate, UserOut

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(admin_only)):
    return db.scalars(select(User).order_by(User.id)).all()


@router.patch("/{user_id}/role", response_model=UserOut)
def update_role(
    user_id: int,
    body: RoleUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_only),
):
    if user_id == admin.id:
        # Prevents the last admin from accidentally locking everyone out.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot change your own role")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    user.role = body.role
    db.commit()
    return user
