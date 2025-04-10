from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from src.api.routers.v1.auth import router as auth_router

app = FastAPI()
app.include_router(auth_router, prefix="/auth", tags=["auth"])

# CORS setup
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins= ["*" ],  # Allow all origins for development purposes
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2PasswordBearer instance for FastAPI token handling
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/")
async def home():
    return {"message": "Welcome to the application!"}
