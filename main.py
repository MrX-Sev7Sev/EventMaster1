from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import os
from dotenv import load_dotenv
import requests
import uuid
import urllib.parse

# Загрузка переменных окружения
load_dotenv()

app = FastAPI()

# Настройки CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключение к PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://mrx:2IAsjs5oOfdEgB2pacpqdPZbhaMOmFN1@dpg-d1aj6jmmcj7s73fjkdu0-a/urfutable")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Настройки JWT
SECRET_KEY = os.getenv("SECRET_KEY", "d2Flf93!kL_42$%k2Qz1@fkEjd*daP2")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Настройки Mail.ru OAuth
MAILRU_CLIENT_ID = os.getenv("890ea7b9c21d4fe98aeccd1a457dc9fcD")
MAILRU_CLIENT_SECRET = os.getenv("19ef2f3739f1461d9adc5894ecfc0f13")
MAILRU_REDIRECT_URI = os.getenv("https://eventmaster-0w4v.onrender.com/auth/vk/callback")
MAILRU_AUTH_URL = "https://oauth.mail.ru/login"
MAILRU_TOKEN_URL = "https://oauth.mail.ru/token"
MAILRU_API_URL = "https://oauth.mail.ru/userinfo"

# Модели SQLAlchemy
class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    mailru_id = Column(String, unique=True, nullable=True)
    is_active = Column(Boolean, default=True)

    def __repr__(self):
        return f"<User {self.username}>"

class Game(Base):
    __tablename__ = "games"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String)
    description = Column(String)
    max_players = Column(Integer)
    current_players = Column(Integer, default=0)
    creator_id = Column(String, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="waiting")
    
    creator = relationship("User", backref="games")

    def __repr__(self):
        return f"<Game {self.title}>"

class PlayerGameAssociation(Base):
    __tablename__ = "player_game_association"
    
    player_id = Column(String, ForeignKey("users.id"), primary_key=True)
    game_id = Column(String, ForeignKey("games.id"), primary_key=True)
    joined_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<PlayerGameAssociation {self.player_id}-{self.game_id}>"

# Создание таблиц
Base.metadata.create_all(bind=engine)

# Модели Pydantic
class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserInDB(UserBase):
    id: str
    mailru_id: Optional[str] = None
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str = None

class GameBase(BaseModel):
    title: str
    description: str
    max_players: int

class GameInDB(GameBase):
    id: str
    current_players: int
    creator_id: str
    created_at: datetime
    status: str

    class Config:
        from_attributes = True

class MailruAuthRequest(BaseModel):
    code: str

# Вспомогательные функции
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(db, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

# Роуты аутентификации
@app.post("/auth/signup", response_model=Token)
async def signup(user: UserCreate, db = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username, 
        email=user.email, 
        hashed_password=hashed_password
    )
    
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Username or email already registered"
                if "unique constraint" in str(e).lower()
                else "Registration error"
            )
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserInDB)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.put("/users/me", response_model=UserInDB)
async def update_user_me(
    update_data: UserBase, 
    current_user: User = Depends(get_current_user), 
    db = Depends(get_db)
):
    try:
        for var, value in update_data.dict().items():
            setattr(current_user, var, value)
        db.commit()
        db.refresh(current_user)
        return current_user
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=400, 
            detail="Error updating user: " + str(e)
        )

# Роуты Mail.ru OAuth
@app.post("/auth/mailru", response_model=Token)
async def mailru_auth(auth_data: MailruAuthRequest, db = Depends(get_db)):
    if not all([MAILRU_CLIENT_ID, MAILRU_CLIENT_SECRET, MAILRU_REDIRECT_URI]):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Mail.ru OAuth not configured properly"
        )

    # Получаем токен от Mail.ru
    token_data = {
        "code": auth_data.code,
        "client_id": MAILRU_CLIENT_ID,
        "client_secret": MAILRU_CLIENT_SECRET,
        "redirect_uri": MAILRU_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    try:
        response = requests.post(MAILRU_TOKEN_URL, data=token_data)
        response.raise_for_status()
        token_response = response.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Mail.ru token error: {str(e)}"
        )

    if "access_token" not in token_response:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No access token in Mail.ru response"
        )

    # Получаем данные пользователя
    try:
        user_response = requests.get(
            MAILRU_API_URL,
            params={"access_token": token_response["access_token"]}
        )
        user_response.raise_for_status()
        user_info = user_response.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to get user info from Mail.ru: {str(e)}"
        )

    if "email" not in user_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No email in user info"
        )

    # Создаем или находим пользователя
    user = db.query(User).filter(User.mailru_id == user_info["email"]).first()
    if not user:
        username = f"mailru_{user_info['email'].split('@')[0]}"
        user = User(
            username=username,
            email=user_info["email"],
            mailru_id=user_info["email"],
        )
        db.add(user)
        try:
            db.commit()
            db.refresh(user)
        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to create user: {str(e)}"
            )

    # Создаем JWT токен
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Роуты игр
@app.get("/games", response_model=List[GameInDB])
async def get_games(
    status: Optional[str] = None, 
    creator_id: Optional[str] = None, 
    db = Depends(get_db)
):
    query = db.query(Game)
    if status:
        query = query.filter(Game.status == status)
    if creator_id:
        query = query.filter(Game.creator_id == creator_id)
    return query.all()

@app.post("/games", response_model=GameInDB)
async def create_game(
    game: GameBase, 
    current_user: User = Depends(get_current_user), 
    db = Depends(get_db)
):
    db_game = Game(
        title=game.title,
        description=game.description,
        max_players=game.max_players,
        creator_id=current_user.id
    )
    db.add(db_game)
    
    # Добавляем создателя в игру
    association = PlayerGameAssociation(
        player_id=current_user.id, 
        game_id=db_game.id
    )
    db.add(association)
    db_game.current_players = 1
    
    try:
        db.commit()
        db.refresh(db_game)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create game: {str(e)}"
        )
    return db_game

@app.post("/games/{game_id}/join")
async def join_game(
    game_id: str, 
    current_user: User = Depends(get_current_user), 
    db = Depends(get_db)
):
    game = db.query(Game).filter(Game.id == game_id).first()
    if not game:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Game not found"
        )
    
    if game.current_players >= game.max_players:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Game is full"
        )
    
    # Проверяем, не присоединен ли уже пользователь
    existing_association = db.query(PlayerGameAssociation).filter(
        PlayerGameAssociation.player_id == current_user.id,
        PlayerGameAssociation.game_id == game_id
    ).first()
    if existing_association:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Already joined this game"
        )
    
    association = PlayerGameAssociation(
        player_id=current_user.id, 
        game_id=game_id
    )
    db.add(association)
    game.current_players += 1
    
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to join game: {str(e)}"
        )
    return {"message": "Successfully joined the game"}

@app.delete("/games/{game_id}")
async def delete_game(
    game_id: str, 
    current_user: User = Depends(get_current_user), 
    db = Depends(get_db)
):
    game = db.query(Game).filter(Game.id == game_id).first()
    if not game:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Game not found"
        )
    
    if game.creator_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the creator can delete the game"
        )
    
    try:
        # Сначала удаляем ассоциации
        db.query(PlayerGameAssociation).filter(
            PlayerGameAssociation.game_id == game_id
        ).delete()
        # Затем удаляем саму игру
        db.delete(game)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to delete game: {str(e)}"
        )
    return {"message": "Game deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
