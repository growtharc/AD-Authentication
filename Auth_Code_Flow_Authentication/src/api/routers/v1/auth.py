from fastapi import APIRouter, Depends, HTTPException, status
from src.api.services.auth_service import AuthenticationService
from fastapi.security import OAuth2PasswordBearer
from fastapi.requests import Request
from fastapi.responses import RedirectResponse
from src.api.schemas.auth import AuthTokenResponse, RefreshTokenRequest,UserInfoResponse
import random, string
from src.api.config.logging import logging

logger = logging.getLogger(__name__)

# Initialize services
auth_service = AuthenticationService()

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Generate a random state string
def generate_state() -> str:
    """Generate a random state string for the OAuth flow."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

# Store states for validation (in-memory or a database in production)
state_store = {}

# Login endpoint (auth code flow, redirects to browser for auth)
@router.get("/login")
async def login():
    """ Initiate the authentication process (for frontend) """
    try:
        state = generate_state()  # Generate state
        state_store[state] = True  # Store the state (use session or DB in real-world apps)
        
        auth_url = await auth_service.get_auth_url(state)
        # print(auth_url)
        logger.info("Generated auth URL: %s", auth_url)
        return RedirectResponse(auth_url)
    
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                             detail="An unexpected error occurred during the login process. Please try again later.")

# Token exchange endpoint (after user logs in, frontend will get the auth code)
@router.get("/callback",response_model = AuthTokenResponse)
async def exchange_auth_code_for_token(request: Request):
    logger.info("Callback URL hit")
    """ Handle the redirect and extract the auth_code from the query params """
    auth_code = request.query_params.get('code')  # MSAL sends the auth_code in the 'code' query param
    state = request.query_params.get('state')

    logger.info(f"Auth code received: {auth_code}")

    if not auth_code:
        raise HTTPException(status_code=400, detail="Authorization code not found.")
    
    if not state or state not in state_store:
        raise HTTPException(status_code=400, detail="Invalid state parameter.")
        
    del state_store[state]
    
    try:  
        # Exchange the auth_code for a token
        token_response = await auth_service.exchange_code_for_token(auth_code)
        group_validation = await auth_service.validate_user_group(token_response.access_token)

        print(f"Token response: {token_response}")
        
        # Redirect to a URL or provide the token response directly
        return token_response
    except Exception as e:
        logger.error(f"Error during token exchange: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred during the token exchange process.")

@router.post("/refresh-token", response_model=AuthTokenResponse)
async def refresh_access_token(request_data: RefreshTokenRequest):
    """ Refresh the access token using the refresh token """
    try:
        token_response = await auth_service.acquire_new_access_token(request_data.refresh_token)
        return token_response
    except Exception as e:
        logger.error(f"Error during token refresh: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred during the token refresh process.")


@router.get("/user-details", response_model=UserInfoResponse)
async def get_user_details(token: str):
    """ Fetch the user details (name, email, etc.) from Microsoft Graph API. """
    try:
        user_info = await auth_service.get_user_info(token)
        return user_info
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)