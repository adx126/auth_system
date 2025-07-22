from fastapi import APIRouter, Depends, HTTPException
from auth_state import auth_instance
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Request
auth_router = APIRouter(prefix="/auth")
from fastapi import Request, HTTPException

async def parse_json(request: Request) -> dict:
    if request.headers.get("content-type") != "application/json":
        raise HTTPException(status_code=400, detail="Expected application/json")
    try:
        return await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or empty JSON body")
    
@auth_router.get("/ping")
async def ping():
    return {"message": "pong"}

@auth_router.post("/register")
async def register(
    request: Request,
    db: AsyncSession = Depends(auth_instance.get_db)
):
    data = await parse_json(request)
    schema = auth_instance.RegisterSchema(**data)
    await auth_instance.create_user_fn(db, schema)
    return {"status": "ok"}

@auth_router.get("/login")
async def login():
    pass