import requests
from fastapi import HTTPException
from src.api.config.config import Config
from src.api.models.auth import TokenData, TokenResponse
from typing import List
import msal
import httpx


class AuthenticationService:
    def __init__(self):
        self.client_id = Config.AZURE_CLIENT_ID
        self.client_secret = Config.AZURE_CLIENT_SECRET
        self.tenant_id = Config.AZURE_TENANT_ID
        self.redirect_uri = Config.AZURE_REDIRECT_URI
        self.authorization_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"
        self.token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        self.scopes = ["User.Read"]
        # self.state_store = {}
        self.msal_app = msal.ConfidentialClientApplication(self.client_id, authority=f"https://login.microsoftonline.com/{self.tenant_id}", client_credential=self.client_secret)

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

    async def get_auth_url(self) -> str:
        """ Generate the auth URL for Authorization Code Flow """
        msal_app = self.msal_app
        return msal_app.get_authorization_request_url(self.scopes, redirect_uri=f"{self.redirect_uri}")

    async def exchange_code_for_token(self, auth_code: str) -> TokenResponse:
        print(f"Authorization code received: {auth_code}")
        try:
            print("Exchanging authorization code for token...")
            token_data = self.msal_app.acquire_token_by_authorization_code(
                auth_code, scopes=self.scopes, redirect_uri=self.redirect_uri
            )
            
            if "access_token" in token_data:
                print("Token acquisition successful.")
                print(f"Access token valid for {token_data.get('expires_in')} seconds.")
                return TokenResponse(
                    access_token=token_data["access_token"],
                    refresh_token=token_data.get("refresh_token"),
                    id_token=token_data.get("id_token"),
                    expires_in=token_data.get("expires_in")
                )
            else:
                error_detail = token_data.get("error_description", "Unknown error")
                print(f"Token acquisition failed: {error_detail}")
                raise HTTPException(status_code=401, detail="Authentication failed")
        except Exception as e:
            print(f"Error during token acquisition: {e}")
            raise HTTPException(status_code=500, detail="Token exchange failed due to server error.")

    async def refresh_token(self,refresh_token: str):
        """ Refresh access token using the stored refresh token. """
        # token_data = self.token_store.get(user_id)
        # if not token_data or "refresh_token" not in token_data:
        #     raise HTTPException(status_code=401, detail="Refresh token missing.")
        try:
            refreshed_data = self.msal_app.acquire_token_by_refresh_token(
                refresh_token, scopes=self.scopes
            )
            if "access_token" in refreshed_data:
                # self.token_store[user_id] = refreshed_data  # Update token in cache
                return refreshed_data
            else:
                raise HTTPException(status_code=401, detail="Failed to refresh token.")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Token refresh failed: {e}")

    # async def get_user_groups(self, token: str) -> List[str]:
    #     """ Fetch group names for the user. """
    #     url = "https://graph.microsoft.com/v1.0/me/memberOf"
    #     headers = {"Authorization": f"Bearer {token}"}
    #     async with httpx.AsyncClient() as client:
    #         response = await client.get(url, headers=headers)
    #         if response.status_code == 200:
    #             groups = response.json().get("value", [])
    #             group_names = []
    #             for group in groups:
    #                 group_name = group.get("displayName")
    #                 if not group_name:  # If name is missing, fetch details
    #                     group_id = group.get("id")
    #                     if group_id:
    #                         group_name = await self.fetch_group_name(group_id, token)
    #                 group_names.append(group_name or "Unknown Group")
    #             return group_names
    #         else:
    #             raise HTTPException(status_code=400, detail="Failed to fetch groups")

    # async def fetch_group_name(self, group_id: str, token: str) -> str:
    #     """ Fetch detailed group information to get its name. """
    #     url = f"https://graph.microsoft.com/v1.0/groups/{group_id}"
    #     headers = {"Authorization": f"Bearer {token}"}
    #     async with httpx.AsyncClient() as client:
    #         response = await client.get(url, headers=headers)
    #         if response.status_code == 200:
    #             return response.json().get("displayName", "Unknown Group")
    #         else:
    #             return "Unknown Group"

    async def get_user_info(self, token: str) -> dict:
        """ Get user info using the access token from Microsoft Graph API """
        headers = {"Authorization": f"Bearer {token}"}
        
        # Fetch user info
        async with httpx.AsyncClient() as client:
            user_info_response = await client.get("https://graph.microsoft.com/v1.0/me", headers=headers)
        if user_info_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user info")
        
        user_info = user_info_response.json()
        user_info['username'] = user_info.get('userPrincipalName', 'Unknown User')

        # Fetch user groups
        async with httpx.AsyncClient() as client:
            groups_response = await client.get("https://graph.microsoft.com/v1.0/me/memberOf", headers=headers)
        if groups_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user groups")
        
        groups = groups_response.json()
        print(groups)
        

        # Add the groups to the user info response
        user_info['groups'] = group_ids = [obj["id"] for obj in groups["value"] if obj["@odata.type"] == "#microsoft.graph.group"]

        print(user_info)

        return user_info

class AuthorizationService:
    def __init__(self, required_groups: List[str] = None
                #  , required_scopes: List[str] = None
                ):
        # Specify the required groups or scopes (roles)
        self.required_groups = required_groups or []
        # self.required_scopes = required_scopes or []
        self.group_id_to_name = {
            "ffe33b6c-c7d0-4144-8f43-ca6b0c9bcbf0": "EDGEAI-DEV",
            "1f21fe73-adeb-4c2f-9bab-d16611f2936f": "ADMIN-ROLE"
        }


    async def authorize_by_groups(self, token_data: TokenData):
        """ Check if the user belongs to the required groups """
        user_group_names = [
            self.group_id_to_name.get(group_id, "Unknown Group") for group_id in token_data.groups
        ]
        missing_groups = [group for group in self.required_groups if group not in user_group_names]
        print(f"missing_groups:{missing_groups}")
        if missing_groups:
            raise HTTPException(status_code=403, detail=f"User lacks the required groups: {', '.join(missing_groups)}")

    # async def authorize_by_scopes(self, token_data: TokenData):
    #     """ Check if the user has the required scopes """
    #     missing_scopes = [scope for scope in self.required_scopes if scope not in token_data.scopes]
    #     if missing_scopes:
    #         raise HTTPException(status_code=403, detail=f"User lacks the required scopes: {', '.join(missing_scopes)}")

    async def authorize(self, token_data: TokenData):
        """ Apply both group and scope-based authorization """
        await self.authorize_by_groups(token_data)
        # self.authorize_by_scopes(token_data)