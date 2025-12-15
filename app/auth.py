from jose import jwt, JWTError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import requests

security = HTTPBearer()

# CONFIG COGNITO
JWKS_URL = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_a0p3hGomx/.well-known/jwks.json"
CLIENT_ID = "7liq97f04uk38mun12drgmpavc"
ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_a0p3hGomx"

# Fetch JWKS một lần (cache)
jwks = requests.get(JWKS_URL).json()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers['kid']
        key = next((k for k in jwks['keys'] if k['kid'] == kid), None)
        if not key:
            raise JWTError("No matching key")

        payload = jwt.decode(
            token=token,
            key=key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token")
    
