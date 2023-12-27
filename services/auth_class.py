from database.database import users
from models.auth_model import UserInDB
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import timedelta, datetime
from core.config import SECRET_KEY, ALGORITHM


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Auth:
    def __init__(self) -> None:
        pass

    async def get_user(self, username: str):
        if(user := users.find_one({"username" : username}, {"_id" : 0})) is not None:
            return UserInDB(**user)
        else:
            return False
        
    async def verify_password(self, plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)
    
    async def get_password_hash(self, password):
        return pwd_context.hash(password)
    
    async def authenticate_user(self, username: str, password: str):
        if not (user := await self.get_user(username)):
            return False
        
        if not await self.verify_password(password, user.password):
            return False
        return user

    def create_access_token(self, data: dict, expires_delta: timedelta | None = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
authentication = Auth()