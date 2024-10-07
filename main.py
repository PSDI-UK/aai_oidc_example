import httpx
import jwt
import json
import requests
from cachetools.func import ttl_cache
from fastapi import FastAPI, Cookie, Request, Response, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode
from pprint import pprint


KEYCLOAK_URL = "your_keycloak_url"
KEYCLOAK_REALM = "your_realm"
KEYCLOAK_CLIENT_ID = "your_client_id"
KEYCLOAK_SECRET = "your_secret"
KEYCLOAK_REDIRECT_URL = "your_redirect_url"
JWT_KEY = "some_long_random_string"

app = FastAPI()


@ttl_cache(ttl=60)
def get_keycloak_public_key():
    # Get JSON Web Key Set from Keycloak so we can verify tokens.
    # This needs to run periodically.
    jwks_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
    jwks = requests.get(jwks_url).json()
    public_keys = {}

    for key in jwks['keys']:
        public_keys[key['kid']] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        
    return public_keys


@app.get("/callback/")
async def callback(request: Request):
    # Get the _code_ parameter to use for Keycloak communication
    code = request.query_params.get("code")

    if not code:
        return HTMLResponse(content="Authorization code not provided.", status_code=400)

    # Make request to Keycloak for a id / access token 
    keycloak_data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_SECRET,
        "redirect_uri": KEYCLOAK_REDIRECT_URL,
        "scope": "openid",
    }
    keycloak_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

    try:
        keycloak_response = httpx.post(keycloak_url, data=keycloak_data)
        keycloak_response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        print(f"Error communicating with Keycloak: {exc.response.text}")
        return HTMLResponse(content="Failed to authenticate with Keycloak.", status_code=exc.response.status_code)

    token_data = keycloak_response.json()
    access_token = token_data.get("access_token")
    
    try:
        # Verify and decode the access token
        headers = jwt.get_unverified_header(access_token)
        public_key = get_keycloak_public_key().get(headers['kid'])
        
        decoded_access_token = jwt.decode(
            access_token, 
            key=public_key,
            audience="account",
            algorithms=['RS256']
        )
    except jwt.InvalidTokenError as e:
        print(f"Failed to verify token: {e}")
        return HTMLResponse(content="Failed to authenticate with Keycloak.", status_code=exc.response.status_code)
   
    print("Decoded Access Token:")
    pprint(decoded_access_token)

    # Create a JWT and set it as a cookie to show that the user is authenticated
    payload = {
        'exp': datetime.utcnow() + timedelta(hours=24),
    }
    logintoken = jwt.encode(payload, JWT_KEY, algorithm='HS256')

    response = RedirectResponse("/")
    response.set_cookie(
        key="logintoken",
        value=logintoken.decode('utf-8'),
        max_age=60 * 60,  # 1 hour
        httponly=True,
    )
    return response


@app.get("/logout", response_class=RedirectResponse)
async def logout(response: Response):
    response = RedirectResponse("/")
    response.delete_cookie("logintoken")
    return response


@app.get("/", response_class=HTMLResponse)
async def root(logintoken: Optional[str] = Cookie(None)):
    # Check for a vaild JWT to see if the use is logged in
    try:      
        jwt.decode(logintoken, JWT_KEY, algorithms=['HS256'])
        isloggedin = True
    except (jwt.InvalidTokenError, jwt.ExpiredSignatureError) as e:
        print(f"Invalid token: {e}")
        isloggedin = False
    
    if isloggedin:
        message = "You are logged in :)"
        buttontext = "Logout"
        url = "/logout"
    else:
        message = "You are not logged in :("
        buttontext = "Login"
        url = (
            f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth?"
            + urlencode({
                'client_id': KEYCLOAK_CLIENT_ID,
                'redirect_uri': KEYCLOAK_REDIRECT_URL,
                'response_type': 'code',
                'scope': 'openid',
            })
        )
        
    return f"""
    <html>
        <head>
            <title>Welcome</title>
        </head>
        <body>
            <h1>{message}</h1>
            <a href="{url}">
                <button type="button">{buttontext}</button>
            </a>
        </body>
    </html>
    """
