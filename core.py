from fastapi import FastAPI, HTTPException
from routes.auth import auth_router
from typing import Callable, AsyncGenerator, Optional, Type, Awaitable, Any
from sqlalchemy.ext.declarative import DeclarativeMeta
from models.default_user import DefaultUserModel
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from . import auth_state
from schemas.register import RegisterSchema as DefaultRegisterSchema
from pydantic import BaseModel
from passlib.hash import bcrypt
from sqlalchemy import select

class AuthModule:
    def __init__(
            self,
            app: FastAPI,
            *,
            get_db: Optional[Callable[[], AsyncGenerator[AsyncSession, None]]] = None,
            user_model: Optional[Type[DeclarativeMeta]] = None,
            secret_key: str,
            database_url: str = "sqlite+aiosqlite:///./auth.db",
            register_schema: Optional[Type[BaseModel]] = None,
            create_user_fn: Optional[Callable[..., Awaitable[Any]]] = None,
            find_user_fn: Optional[Callable[[AsyncSession, BaseModel], Awaitable[Any]]] = None,
            login_user_fn: Optional[Callable[[AsyncSession, BaseModel], Awaitable[Any]]] = None,
    ):
        self.app = app
        self.user_model = user_model or DefaultUserModel
        self.register_schema = register_schema or DefaultRegisterSchema
        self.secret_key = secret_key

        self.get_db = get_db or self._create_default_get_db(database_url)

        self.create_user_fn = create_user_fn or self._default_create_user
        self.find_user_fn = find_user_fn or self._default_find_user
        self.login_user_fn = login_user_fn or self._default_login_user

        self.include_routes()

        auth_state.auth_instance = self

    def _create_default_get_db(self, db_url: str):
        engine = create_async_engine(db_url, echo=True)
        SessionLocal = async_sessionmaker(bind = engine, expire_on_commit=False)

        async def get_db():
            async with SessionLocal() as session:
                yield session
        
        return get_db

    def include_routes(self):
        self.app.include_router(auth_router)

    async def _default_create_user(self, db: AsyncSession, **user_data):
        if "password" in user_data:
            user_data["hashed_password"] = bcrypt.hash(user_data.pop("password"))
        else:
            raise HTTPException(status_code=422, detail="No password provided")
        user = self.user_model(**user_data)
        if await self.find_user_fn(db, user_data):
            raise HTTPException(status_code=401, detail="User already exists")
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
