from pydantic import BaseModel, EmailStr, constr

class RegisterSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=6)