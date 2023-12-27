from fastapi import APIRouter, Body, status, HTTPException, Depends
from models.auth_model import UserRegisterModel, UserLoginModel
from models.response_model import UserRegisteredModel, UserRegisterError
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from typing import Annotated
from datetime import timedelta
from core.config import ACCESS_TOKEN_EXPIRE_MINUTES

from core.utils import error_response
from database.database import users
from services.auth_class import authentication


router = APIRouter()


@router.post("/register")
async def user_register(request: UserRegisterModel = Body(...)):
    try:
        if (user := users.find_one({"$or": [{"username" : request.username},{"mobile_number" : request.contact}] })) is None:            
            get_password_hash = await authentication.get_password_hash(request.password)
            request.password = get_password_hash
            users.insert_one(request.model_dump())
            
            return JSONResponse(
                content = UserRegisteredModel(
                    reference_id=request.reference_id,
                    username=request.username,
                    email_id=request.email_id,
                    created_at= str(request.created_at)
                ).model_dump(),
                status_code = status.HTTP_201_CREATED
            )
        
        else:
            return error_response(
                code = "E101", 
                description = "Username or mobile already exists"
            )
        
    except Exception as err:
        return str(err)


@router.post("/login")
async def user_login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    try:
        user = await authentication.authenticate_user(form_data.username, form_data.password)
        if not user:
            return error_response(
                code = "E102", 
                description = "Incorrect username or password"
            )
        
        access_token_expires = timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = authentication.create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as err:
        return str(err)
