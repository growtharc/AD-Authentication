import requests
from fastapi import HTTPException, status
from src.api.config.config import CLIENT_ID, CLIENT_SECRET, TENANT_ID, REDIRECT_URI, AUTHORITY, GRAPH_ENDPOINT, SCOPES,AD_GROUP_AUTH
from src.api.schemas.auth import AuthTokenResponse
from typing import List
import msal
import httpx
from src.api.config.logging import logging

logger = logging.getLogger(__name__)


class AuthenticationService:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.client_secret = CLIENT_SECRET
        self.tenant_id = TENANT_ID
        self.redirect_uri = REDIRECT_URI
        self.authorization_url = f"{REDIRECT_URI}/oauth2/v2.0/authorize"
        self.token_url = f"{REDIRECT_URI}/oauth2/v2.0/token"
        self.authority = AUTHORITY
        self.graph_endpoint = GRAPH_ENDPOINT
        self.scopes = SCOPES
        self.ad_group_auth = AD_GROUP_AUTH
        self.group_id_to_name = {
                "ffe33b6c-c7d0-4144-8f43-ca6b0c9bcbf0": "EDGEAI-DEV",
                "1f21fe73-adeb-4c2f-9bab-d16611f2936f": "ADMIN-ROLE"
            }
    #     self.state_store = {}


    # def store_state(self, user_id, state):
        
    #     self.state_store[user_id] = state  # Associate state with the user_id

    # def validate_state(self,user_id, state):
    #     """
    #     Validates the state for the specific user.
    #     """
    #     if self.state_store.get(user_id) == state:
    #         # Remove the state after validation to prevent reuse
    #         del self.state_store[user_id]
    #         return True
    #     return False


    async def get_auth_url(self,state: str) -> str:
        """ Generate the auth URL for Authorization Code Flow """
        try:
            msal_app = msal.PublicClientApplication(self.client_id, authority=self.authority)
            print(self.redirect_uri, self.authority)     
            print(self.client_id,self.client_secret)
            return msal_app.get_authorization_request_url(self.scopes, redirect_uri=self.redirect_uri,state = state)
        
        except Exception as e:
            logger.error(f"Unexpected error while generating auth URL: {str(e)}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="An unexpected error occurred while generating the authentication URL.")

    async def exchange_code_for_token(self, auth_code: str) -> AuthTokenResponse:
        try:
            msal_app = msal.ConfidentialClientApplication(self.client_id, authority=self.authority, client_credential=self.client_secret)
            token_data = msal_app.acquire_token_by_authorization_code(auth_code, scopes=self.scopes, redirect_uri=self.redirect_uri)
            
            if "access_token" in token_data:
                return AuthTokenResponse(
                    access_token=token_data["access_token"],
                    token_type=token_data.get("token_type", "Bearer"),
                    refresh_token=token_data.get("refresh_token"),
                    id_token=token_data.get("id_token"),
                    expires_in=token_data.get("expires_in")
                )
            else:
                # Handle specific error codes returned by MSAL
                if "error" in token_data:
                    error_code = token_data["error"]
                    if error_code == "invalid_grant":
                        logger.error("Authorization code has expired or is invalid.")
                        raise HTTPException(status_code=400, detail="Authorization code has expired or is invalid.")
                    elif error_code == "invalid_client":
                        logger.error("Invalid client credentials.")
                        raise HTTPException(status_code=401, detail="Invalid client credentials.")
                    elif error_code == "invalid_request":
                        logger.error("The request is malformed.")
                        raise HTTPException(status_code=400, detail="The request is malformed.")
                    elif error_code == "access_denied":
                        logger.error("User has denied the required permissions.")
                        raise HTTPException(status_code=403, detail="User has denied the required permissions.")
                    else:
                        logger.error(f"Unknown error from MSAL: {token_data.get('error_description', 'No description available')}")
                        raise HTTPException(status_code=500, detail="An unexpected error occurred during the token exchange.")
                raise HTTPException(status_code=500, detail="Failed to obtain access token.")

        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {str(e)}")
            raise HTTPException(status_code=500, detail="An unexpected error occurred. Please try again later.")
    
    async def acquire_new_access_token(self, refresh_token: str) -> AuthTokenResponse:        
        """ Refresh access token using the stored refresh token. """
        msal_app = msal.ConfidentialClientApplication(self.client_id, authority=self.authority, client_credential=self.client_secret)
        try:
            refreshed_data = msal_app.acquire_token_by_refresh_token(
                refresh_token, scopes=self.scopes
            )
            
            # If the refresh is successful and we have a new access token, return the refreshed data
            if "access_token" in refreshed_data:
                # Optionally, update your token store here if needed
                # self.token_store[user_id] = refreshed_data
                return refreshed_data

            # Handle specific MSAL error codes or generic failure
            if "error" in refreshed_data:
                error_code = refreshed_data["error"]
                error_description = refreshed_data.get("error_description", "No error description.")
                
                if error_code == "invalid_grant":
                    logger.error(f"Invalid grant error: {error_description}")
                    raise HTTPException(status_code=400, detail="Invalid refresh token.")
                elif error_code == "expired_token":
                    logger.error(f"Expired token: {error_description}")
                    raise HTTPException(status_code=401, detail="Refresh token has expired.")
                elif error_code == "invalid_client":
                    logger.error(f"Invalid client credentials: {error_description}")
                    raise HTTPException(status_code=401, detail="Invalid client credentials.")
                else:
                    logger.error(f"Unknown MSAL error: {error_description}")
                    raise HTTPException(status_code=500, detail=f"Unknown error: {error_description}")
            
            # If token exchange failed, raise an appropriate error
            raise HTTPException(status_code=500, detail="Failed to refresh token: unknown reason.")
        
        except Exception as e:
            # Handle any other unexpected errors
            logger.error(f"Unexpected error during token refresh: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Token refresh failed: {str(e)}")

    async def validate_user_group(self, token: str) -> bool:
        """ Validate if the user belongs to a specific Azure AD group """
        try:
            headers = {"Authorization": f"Bearer {token}"}

            async with httpx.AsyncClient() as client:
                response = await client.get(f'{self.graph_endpoint}/me/memberOf', headers=headers)

            # --- Handle specific status codes ---
            if response.status_code == 401:
                raise HTTPException(status_code=401, detail="Access token is invalid or expired")

            elif response.status_code == 403:
                raise HTTPException(status_code=403, detail="User is not authorized to access group information")

            elif response.status_code >= 400:
                raise HTTPException(status_code=response.status_code, detail=f"Unexpected error: {response.text}")

            # --- Parse valid response ---
            groups = response.json()
            group_ids = [group['id'] for group in groups.get('value', [])]
            group_names = [self.group_id_to_name[group_id] for group_id in group_ids if group_id in self.group_id_to_name]
            print(f"User groups: {group_ids} \n Group names: {group_names}")
            logger.info(f"User groups: {group_ids} \n Group names: {group_names}")

            # --- Case-insensitive group check ---
            if self.ad_group_auth.lower() not in [group.lower() for group in group_names]:
                raise HTTPException(status_code=403, detail="User does not belong to the required group")

            return True

        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Network error occurred: {str(e)}")

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Group validation failed: {str(e)}")

    async def get_user_info(self, token: str) -> dict:
        """ Get user info using the access token from Microsoft Graph API """
        try:
            headers = {"Authorization": f"Bearer {token}"}
            
            # Fetch user info from Microsoft Graph API (basic information)
            async with httpx.AsyncClient() as client:
                user_info_response = await client.get(f'{self.graph_endpoint}/me', headers=headers)
            
            if user_info_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to fetch user info")
            
            elif user_info_response.status_code == 401:
                raise HTTPException(status_code=401, detail="Access token is invalid or expired")

            elif user_info_response.status_code == 403:
                raise HTTPException(status_code=403, detail="User is not authorized to access group information")

            elif user_info_response.status_code >= 400:
                raise HTTPException(status_code=user_info_response.status_code, detail=f"Unexpected error: {user_info_response.text}")
            
            user_info = user_info_response.json()
            print(user_info)
            logger.info(f"User info: {user_info}")

            # Fetch user groups
            async with httpx.AsyncClient() as client:
                groups_response = await client.get(f'{self.graph_endpoint}/me/memberOf', headers=headers)
            
            if groups_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to fetch user groups")
            
            groups = groups_response.json()

            # Add the groups to the user info response
            group_ids = [group['id'] for group in groups.get('value', [])]            
            user_info['groups'] = [self.group_id_to_name[group_id] for group_id in group_ids if group_id in self.group_id_to_name]

            # Add additional user details (such as email, job title, etc.)
            user_info['user_principal_name'] = user_info.get('userPrincipalName')
            user_info['given_name'] = user_info.get('givenName')
            user_info['surname'] = user_info.get('surname')
            user_info['display_name'] = user_info.get('displayName')
            user_info['job_title'] = user_info.get('jobTitle')
            user_info['mobile_phone'] = user_info.get('mobilePhone')
            user_info['preferred_language'] = user_info.get('preferredLanguage')


            return user_info
        except Exception as e:
            logger.error(f"Unexpected error while fetching user info: {str(e)}")
            raise HTTPException(status_code=500, detail="An unexpected error occurred while fetching user info.")
