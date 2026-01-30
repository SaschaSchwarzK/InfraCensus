from __future__ import annotations

from fastapi import APIRouter

from central.web.routes.tenants.collectors import router as collectors_router
from central.web.routes.tenants.credentials import router as credentials_router
from central.web.routes.tenants.exports import router as exports_router
from central.web.routes.tenants.index import router as index_router
from central.web.routes.tenants.networks import router as networks_router
from central.web.routes.tenants.schedules import router as schedules_router
from central.web.routes.tenants.sites import router as sites_router
from central.web.routes.tenants.users import router as users_router

router = APIRouter()
router.include_router(index_router)
router.include_router(sites_router)
router.include_router(networks_router)
router.include_router(schedules_router)
router.include_router(collectors_router)
router.include_router(exports_router)
router.include_router(credentials_router)
router.include_router(users_router)
