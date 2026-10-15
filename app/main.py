from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.auth import router as auth_router
from app.core.config import settings
from app.database.base import Base
from app.database.session import engine
from app.services.email_service import EmailDeliveryError

app = FastAPI(title=settings.app_name, version="1.0.0", docs_url="/docs")

origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(EmailDeliveryError)
async def email_delivery_error_handler(request: Request, exc: EmailDeliveryError) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "Email delivery is temporarily unavailable. Configure SMTP and retry."},
    )


app.include_router(auth_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
