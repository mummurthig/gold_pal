from pydantic import (BaseModel, Field, UUID4)
from datetime import datetime
import uuid
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserRegisterModel(BaseModel):
    reference_id: str | None = str(uuid.uuid4())
    username: str = Field(...)
    name:  str = Field(...)
    contact:  str = Field(...)
    email_id:  str = Field(...)
    password:  str = Field(...)
    address:  str | None = None
    city:  str | None = None
    state:  str | None = None
    country:  str | None = None
    created_at : datetime | None = datetime.now()
    is_active: bool = True

    def hash_password(self):
        self.password = pwd_context.hash(self.password)

class UserLoginModel(BaseModel):
    username: str = Field(...)
    password: str = Field(...)

class User(BaseModel): 
    reference_id : str   
    username: str
    name: str
    email_id: str
    contact: str
    address:  str | None = None
    city:  str | None = None
    state:  str | None = None
    country:  str | None = None
    is_active: bool
    created_at : datetime


class TokenData(BaseModel):
    username: str | None = None

class Token(BaseModel):
    access_token: str
    token_type: str

class UserInDB(User):
    password: str


