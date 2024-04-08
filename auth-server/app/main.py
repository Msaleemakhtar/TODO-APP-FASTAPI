from typing import Optional, Annotated
from sqlmodel import Session

from fastapi import Depends, HTTPException, status, FastAPI
from fastapi.security import OAuth2PasswordRequestForm

from uuid import UUID
from contextlib import asynccontextmanager



from app.service import user_login_for_access_token, user_signup, get_gpt_token, create_access_token
from app.models import UserRegister, GptToken, UserOutput, LoginResponse
from app.core.config_db import get_db, create_db_and_tables
from app.core.utils import get_current_user_id




@asynccontextmanager
async def create_table(app:FastAPI):
    print("creating Table")
    create_db_and_tables()
    yield

app:FastAPI = FastAPI(
    lifespan=create_table,
      title="Multi-User OAuth Server",
    description="Multi-User Todo-App OAuth_Microservice",
    version="1.0.0",
    contact={
        "name": "Muhammad Saleem Akhtar",
        "email": "saleemakhtar864@gmail.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html"
    },
    docs_url="/api/docs"
)



@app.post("/api/oauth/login",response_model=LoginResponse, tags=["OAuth2 Authentication"])
async def login_authorization(form_data:Annotated[OAuth2PasswordRequestForm, Depends()], db: Annotated[Session, Depends(get_db)]):
    try:
        return await user_login_for_access_token(form_data, db)
      
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    


@app.post("/api/oauth/signup", response_model=UserOutput, tags=["OAuth2 Authentication"])
async def signup(user_data:UserRegister, db:Annotated[Session, Depends(get_db)]):
    
    return await user_signup(user_data, db)
       
  


@app.get("/api/user/me", tags=["User"])
async def get_current_user(user_id: Annotated[UUID, Depends(get_current_user_id)]):
    return user_id