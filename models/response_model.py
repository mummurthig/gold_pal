from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class UserRegisteredModel(BaseModel):
    
    reference_id: str
    username: str
    email_id : str
    created_at : str | None = None

class UserRegisterErrorResponse(BaseModel):
    code: str | None = "USER_EXISTS"
    description: str | None = "User already exists"
    source: str | None =  "NA"
    step: str | None =  "NA"
    reason: str | None =  "NA"

class UserRegisterError(BaseModel):
    error = UserRegisterErrorResponse
