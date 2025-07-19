from fastapi import FastAPI
from core import AuthModule

app = FastAPI()
auth = AuthModule(app)

@app.get("/")
async def hello():
    return {"message": "hello"}