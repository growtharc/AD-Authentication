from fastapi import APIRouter, Depends, HTTPException
from src.api.models.auth import TokenData, TokenResponse
from src.api.services.auth_service import AuthenticationService, AuthorizationService
from fastapi.security import OAuth2PasswordBearer
from fastapi.requests import Request
from fastapi.responses import RedirectResponse
import uuid

# Initialize services
auth_service = AuthenticationService()
authorization_service = AuthorizationService(required_groups=["EDGEAI-DEV"]
                                            #  , required_scopes=["read:data"]
                                            )

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

@router.get("/")
async def home():
    return {"message": "Welcome to the application!"}

# Login endpoint (auth code flow, redirects to browser for auth)
@router.get("/login")
async def login(request: Request):
    # user_id = str(uuid.uuid4())  # Generate a temporary user identifier (or use session ID)
    # state = str(uuid.uuid4())  # Generate unique state
    # auth_service.store_state(user_id, state)  # Store state for this user
    response = await auth_service.get_auth_url()
    return RedirectResponse(url=response)

# Token exchange endpoint (after user logs in, frontend will get the auth code)
@router.get("/getAToken")
async def get_access_token(request: Request, code: str):
    # Validate user_id and state
    # if not auth_service.validate_state(user_id, state):  # Ensure state matches the stored value
    #     raise HTTPException(status_code=400, detail="Invalid state parameter")
    # print(user_id)
    print("get_access_token called")
    result = await auth_service.exchange_code_for_token(code)
    print("Result:", result)

    # Check if result is a Pydantic model, and use `.model_dump()` if applicable
    if hasattr(result, "model_dump"):  # For Pydantic v2.0 or later
        result = result.model_dump()

    if result is None:
        raise HTTPException(status_code=400, detail="Token exchange returned None.")

    if "access_token" in result:
        # return {"message": "Authentication successful!"}
        return result
    else:
        print("Access token not found in result:", result)
        raise HTTPException(status_code=400, detail="Failed to acquire token")

# Endpoint that requires authentication and authorization
@router.get("/user_info")
async def get_user_info(token: str = Depends(oauth2_scheme)):
    """ Get user info if the token is valid and user is authorized """
    # Decode the token and get the user info
    token_data = await auth_service.get_user_info(token)
    
    # Use the AuthorizationService to check if the user is allowed
    await authorization_service.authorize(TokenData(**token_data))
    print("User info:", token_data)
    return token_data
