from pydantic import BaseModel, EmailStr

class UserSignupSchema(BaseModel):
    email: EmailStr
    password: str
    display_name: str | None = None

class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str

class UserResponseSchema(BaseModel):
    uid: str
    email: EmailStr
    display_name: str | None = None
