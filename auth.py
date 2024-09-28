from typing import Annotated
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException,status
from pydantic import BaseModel
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt

auth_router = APIRouter()

# this tokenUrl arg is only used so the documentation page knows which endpoint to hit when we login using the interactive login form of swagger
# and this OAuth2PasswordBearer when added as a type to any of the function it will take the token from the request's authorization header and remove the bearer from the front of it
# also fastapi will add the padlock symbol in front of that api so we can login just before using it
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/auth/login")

SECRET_KEY = "xH1fIgsTLC8PCN3BQwgFJXvSxx753idA"
ALGORITHM = "HS256"

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class CreateUserReq(BaseModel):
    email: str
    password: str


def create_access_token(email: str, expires_delta: timedelta):
    encode = {"sub": email}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({"exp": expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

def validate_token(token : Annotated[str,Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        email:str = payload.get("sub") 
        return email 
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,details="Token has expired")

@auth_router.post("/signup")
async def create_user(
    create_user_req: CreateUserReq,
):
    user_model = Users(
        email=create_user_req.email,
        password=bcrypt_context.hash(create_user_req.password),
    )
    return user_model


@auth_router.post("/login")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    return create_access_token(form_data.username, timedelta(seconds=100))


@auth_router.get("/")
def test_auth_route():
    print(oauth2_bearer)
    return True


@auth_router.get("/this_is_locked_route")
def locked_route(token: Annotated[oauth2_bearer, Depends()]):
    return validate_token(token) 
