from dotenv import load_dotenv
import os

# print(os.get_cwd())
print(os.path.dirname(__file__))
# Load environment variables from .env file
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)


CLIENT_ID = os.getenv("AD_CLIENT_ID")
print(CLIENT_ID)
CLIENT_SECRET = os.getenv("AD_CLIENT_SECRET")
TENANT_ID = os.getenv("AZURE_TENANT_ID")
REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["https://graph.microsoft.com/.default"]
GRAPH_ENDPOINT = os.getenv("AZURE_GRAPH_ENDPOINT")
AD_GROUP_AUTH = os.getenv("AZURE_REQUIRED_GROUP")