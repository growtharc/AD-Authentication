from pydantic import BaseModel
from typing import Optional, List


class AuthCodeRequest(BaseModel):
    """Schema for the request body containing the authorization code."""
    code: str

class AuthTokenResponse(BaseModel):
    """Schema for the response containing the access token."""
    access_token: str  # The actual access token
    token_type: str  # Usually "bearer"
    refresh_token: str  # Optional, used for refreshing the access token
    id_token: str  # ID token, usually a JWT containing user info
    expires_in: int  # Token expiration time in seconds

# class AuthStateValidationResponse(BaseModel):
#     """Schema for validating the state parameter in the callback."""
#     valid: bool
#     message: str

class RefreshTokenRequest(BaseModel):
    """Schema for the request body containing the refresh token."""
    refresh_token: str  # The refresh token to be used for obtaining a new access token

class UserInfoResponse(BaseModel):
    """Schema to represent user details fetched from Microsoft Graph API."""
    # id: str  # User ID
    display_name: str  # Full Name of the user
    given_name: str  # First Name
    surname: str  # Last Name
    user_principal_name: str  # Email (UPN)
    job_title: Optional[str]  # Job title (if available)
    mobile_phone: Optional[str]  # Mobile phone number (if available)
    preferred_language: Optional[str]  # Preferred language (if available)
    groups: List[str]  # List of user groups