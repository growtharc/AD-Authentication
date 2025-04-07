import requests
import webbrowser

BASE_URL = "http://127.0.0.1:8000/auth"

def get_tokens():
    """
    Step 1: Get the tokens by triggering the login flow.
    """
    login_response = requests.get(f"{BASE_URL}/login", allow_redirects=True)

    if login_response.status_code == 200:
        # Extract the login URL from the response
        login_url = login_response.url
        print("Login URL opened in browser:", login_url)
       
        # Open the login URL in the default web browser
        webbrowser.open(login_url)

        # return {"message":"Token received on UI"}  
        return None
    else:
        raise Exception(f"Unexpected response: {login_response.status_code}")

def get_user_details (token):
    """
    Step 2: Get user details using the access token.
    """
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(f"{BASE_URL}/user_info", headers=headers)
    # print("User Details:", response.json())

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to get user details: {response.status_code}")

if __name__ == "__main__":
    # access_token= None
    try:
        if access_token is None:
            # Step 1: Get the tokens

            access_token = get_tokens()
            print(access_token)

        # Step 2: Test the protected endpoint
        text = get_user_details(access_token)
        print(text)

    except Exception as e:
        print(f"Error: {e}")
