import os

from dotenv import load_dotenv

# Load environment variables from .env file
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)


class Config:
    AZURE_CLIENT_ID = os.getenv("CLIENT_ID")
    AZURE_CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    AZURE_TENANT_ID = os.getenv("TENANT_ID")
    AZURE_REDIRECT_URI = os.getenv("REDIRECT_URI")
    LOGGING_LEVEL = os.getenv("LOGGING_LEVEL", "INFO")

    # Debug print to check values
    print(f"CLIENT_ID: {AZURE_CLIENT_ID}")
    print(f"CLIENT_SECRET: {AZURE_CLIENT_SECRET}")
    print(f"TENANT_ID: {AZURE_TENANT_ID}")
    print(f"REDIRECT_URI: {AZURE_REDIRECT_URI}")
    print(f"LOGGING_LEVEL: {LOGGING_LEVEL}")
    print("Current working directory:", os.getcwd())
