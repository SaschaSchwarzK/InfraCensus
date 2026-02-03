from __future__ import annotations

from fastapi import APIRouter

from central.web.routes.admin import router as admin_router
from central.web.routes.auth_routes import router as auth_router
from central.web.routes.home import router as home_router
from central.web.routes.tenants import router as tenants_router

router = APIRouter()
router.include_router(home_router)
router.include_router(auth_router)
router.include_router(tenants_router)
router.include_router(admin_router)
