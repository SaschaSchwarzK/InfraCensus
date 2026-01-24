from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from central.api.collector import router as collector_router
from central.web.app import router as web_router
from central.core.config import settings

app = FastAPI(title="InfraCensus Central API")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)
app.include_router(web_router)
app.include_router(collector_router)


@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok"}
