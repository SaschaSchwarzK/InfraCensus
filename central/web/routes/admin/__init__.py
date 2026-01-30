from __future__ import annotations

from fastapi import APIRouter

from central.web.routes.admin.audit import router as audit_router
from central.web.routes.admin.schedules import router as schedules_router
from central.web.routes.admin.tenants import router as tenants_router
from central.web.routes.admin.users import router as users_router

router = APIRouter()
router.include_router(tenants_router)
router.include_router(schedules_router)
router.include_router(users_router)
router.include_router(audit_router)
