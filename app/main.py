from fastapi import FastAPI

from app.api.alerts import router as alerts_router
from app.api.detections import router as detections_router
from app.api.events import router as events_router


app = FastAPI(
    title="Hybrid Threat Detection Engine",
    description="A security event detection and alert correlation platform.",
    version="0.1.0",
)


app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(detections_router)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "Hybrid Threat Detection Engine",
        "version": "0.1.0",
        "status": "operational",
    }


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy"}