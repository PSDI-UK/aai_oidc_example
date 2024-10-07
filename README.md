# Example OIDC login with FastAPI

This OIDC Example service demonstrates the implementation of the OIDC Authorisation Code Flow. It is a FastAPI web service that can be linked up to Keycloak for user authentication and authorisation.

When you access the OIDC Example service, it will display a message telling you to login alongside a login button. Clicking login will redirect you to the Keycloak login page, where you can enter your credentials. Upon successful authentication, Keycloak redirects you back to the OIDC Example service (/callback) with an authorization code. This code is exchanged with keycloak for an Access Token. The service then creates a JSON Web Token (JWT) indicating the user is logged in which causes the message to change and turn the login button to logout.

The access token is a dictionary that contains information such as the user's name, email, roles, groups. Information available to the service can be configured on a client by client basis. The **sub** (subject claim) can be used as a unique user identifier.

You will need to supply few config values before you start the OIDC Example service. **KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_SECRET** should be obtained from the Keycloak admin. Specifically, **KEYCLOAK_CLIENT_ID, KEYCLOAK_SECRET** will be unique to your deployment.

The **KEYCLOAK_REDIRECT_URL** value is set in Keycloak and is a formal part of the process. If you change the path of the callback in your application, this also needs to be updated in Keycloak otherwise the request will be rejected.

The **JWT_KEY** just needs to be a random string. It is used to create a signed JWT to simulate a basic user login.


## Setup

Ensure you have Python 3.10 or higher installed. Follow these steps to set up your environment:

```bash
# Create a virtual environment
python3 -m venv oidcenv

# Activate the virtual environment
source ./oidcenv/bin/activate

# Upgrade pip
python3 -m pip install --upgrade pip

# Install the required dependencies
pip install -r requirements.txt
```

The service will be available at http://hostname:8000.
