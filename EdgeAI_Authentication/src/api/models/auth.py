from pydantic import BaseModel
from typing import List, Optional

class TokenData(BaseModel):
    username: str
    groups: List[str]

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None

class AuthorizationError(BaseModel):
    error_code: str  # Code indicating the error type (e.g., "token_expired")
    error_description: str  # Detailed description of the error
