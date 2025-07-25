from fastapi import FastAPI, HTTPException
from typing import Callable, AsyncGenerator, Optional, Type, Awaitable, Any
from sqlalchemy.ext.declarative import DeclarativeMeta
from models.default_user import DefaultUserModel
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
import auth_state
from schemas.register import RegisterSchema as DefaultRegisterSchema
from schemas.login import LoginSchema as DefaultLoginSchema
from pydantic import BaseModel
from passlib.hash import bcrypt
from sqlalchemy import select
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone

class AuthModule:
    def __init__(
            self,
            app: FastAPI,
            *,
            get_db: Optional[Callable[[], AsyncGenerator[AsyncSession, None]]] = None,
            user_model: Optional[Type[DeclarativeMeta]] = DefaultUserModel,
            secret_key: str = "defaultsecretkey",
            database_url: str = "sqlite+aiosqlite:///./auth.db",
            register_schema: Optional[Type[BaseModel]] = DefaultRegisterSchema,
            login_schema: Optional[Type[BaseModel]] = DefaultLoginSchema,
            create_user_fn: Optional[Callable[..., Awaitable[Any]]] = None,
            find_user_fn: Optional[Callable[[AsyncSession, BaseModel], Awaitable[Any]]] = None,
            login_user_fn: Optional[Callable[[AsyncSession, BaseModel], Awaitable[Any]]] = None,
            jwt_expire_min: int = 15,
            jwt_algorithm: str = "HS256",
    ):
        self.app = app
        self.user_model = user_model

        self.RegisterSchema = register_schema

        self.LoginSchema = login_schema

        self.secret_key = secret_key

        self.jwt_expire_min = jwt_expire_min
        self.jwt_algorithm = jwt_algorithm

        self.get_db = get_db or self._create_default_get_db(database_url)

        self.create_user_fn = create_user_fn or self._default_create_user
        self.find_user_fn = find_user_fn or self._default_find_user
        self.login_user_fn = login_user_fn or self._default_login_user

        auth_state.auth_instance = self

        self.include_routes()

    def _create_default_get_db(self, db_url: str):
        from models import default_user

        engine = create_async_engine(db_url, echo=True)
        SessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def create_tables():
            async with engine.begin() as conn:
                await conn.run_sync(default_user.Base.metadata.create_all)

        @self.app.on_event("startup")
        async def startup():
            await create_tables()

        async def get_db():
            async with SessionLocal() as session:
                yield session

        return get_db

    def include_routes(self):
        from routes.auth import auth_router
        self.app.include_router(auth_router)

    async def _default_create_user(self, db: AsyncSession, user_data: BaseModel):
        user_dict = user_data.dict()

        if "password" in user_dict:
            user_dict["hashed_password"] = bcrypt.hash(user_dict.pop("password"))
        else:
            raise HTTPException(status_code=422, detail="No password provided")

        if await self.find_user_fn(db, user_data):
            raise HTTPException(status_code=401, detail="User already exists")

        user = self.user_model(**user_dict)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user
    
    async def _default_find_user(self, db: AsyncSession, user_data: BaseModel):
        value = getattr(user_data, "email", None)
        if not value:
            raise HTTPException(status_code=422, detail="No email provided")
        
        model = self.user_model
        result = await db.execute(select(model).where(model.email == value))
        return result.scalar_one_or_none()
    
    async def _default_login_user(self, db: AsyncSession, user_data: BaseModel):
        email = getattr(user_data, "email", None)
        password = getattr(user_data, "password", None)

        if not email or not password:
            raise HTTPException(status_code=422, detail="Email and password required")

        model = self.user_model
        result = await db.execute(select(model).where(model.email == email))
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        if not bcrypt.verify(password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid password")

        return user
    
    def _default_create_jwt(self, data: BaseModel, expires_delta: timedelta | None = None):
        user_data = data.dict()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=self.jwt_expire_min))
        user_data.update({"exp": int(expire.replace(tzinfo=timezone.utc).timestamp())})
        encoded_jwt = jwt.encode(user_data, self.secret_key, algorithm=self.jwt_algorithm)
        return encoded_jwt
    
    def _default_verify_jwt(self, token: str):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.jwt_algorithm])
            return payload
        except JWTError as e:
            raise HTTPException(status_code=401, detail="Invalid or expired token")