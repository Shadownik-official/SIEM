from fastapi import APIRouter
from ..auth import require_auth

router = APIRouter()

@router.get("/system")
@require_auth(permissions=['read:metrics'])
async def get_system_metrics(user: dict):
    # Your metrics logic here
    return {
        "cpu": 45.2,
        "memory": 62.8,
        "disk": 78.1
    } 