from fastapi import APIRouter, Depends, HTTPException
from auth_state import auth_instance
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.hash import bcrypt
from models.default_user import DefaultUserModel

auth_router = APIRouter(prefix="/auth")

@auth_router.get("/ping")
async def ping():
    return {"message": "pong"}

@auth_router.post("/register")
async def register(
    user_data = Depends(auth_instance.register_schema),
    db : AsyncSession = Depends(auth_instance.get_db)
):
    pass

@auth_router.get("/login")
async def login():
    pass