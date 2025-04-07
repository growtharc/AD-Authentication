from fastapi import FastAPI
from src.api.routers.v1.auth import router as auth_router

app = FastAPI()

# Include the router for authentication and authorization
app.include_router(auth_router, prefix="/auth", tags=["auth"])
