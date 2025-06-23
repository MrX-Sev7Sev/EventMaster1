from sqlalchemy.orm import Session 
from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
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
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Загрузка переменных окружения
load_dotenv()

app = FastAPI()

# Настройки CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://table-games.netlify.app",
        "http://localhost:3000",
        "http://localhost:5173",
        "https://eventmaster2.onrender.com" # Для разработки
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Authorization"]
)

# Подключение к PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://mrx:gQ9KMhmhQsklSywRRWpsT2lyETBdjdqi@dpg-d1cg0ibe5dus73fh8io0-a/urfutable_vr3m")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Настройки JWT
SECRET_KEY = os.getenv("SECRET_KEY", "d2еlf43!kL_42$%k42Qwgaa1@fkEjd*daP2")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# Настройки Mail.ru OAuth
MAILRU_CLIENT_ID = os.getenv("MAILRU_CLIENT_ID")
MAILRU_CLIENT_SECRET = os.getenv("MAILRU_CLIENT_SECRET")
MAILRU_TOKEN_URL = "https://oauth.mail.ru/token"
MAILRU_API_URL = "https://oauth.mail.ru/userinfo"

# Модели SQLAlchemy
class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)  # Этот столбец должен быть!
    mailru_id = Column(String, unique=True, nullable=True)
    is_active = Column(Boolean, default=True)

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

class PlayerGameAssociation(Base):
    __tablename__ = "player_game_association"
    player_id = Column(String, ForeignKey("users.id"), primary_key=True)
    game_id = Column(String, ForeignKey("games.id"), primary_key=True)
    joined_at = Column(DateTime, default=datetime.utcnow)

# Создание таблиц
def reset_database():
    Base.metadata.drop_all(bind=engine)  # Удалить все таблицы
    Base.metadata.create_all(bind=engine)  # Создать заново

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
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Not authenticated")  # Здесь возникает ошибка

@app.get("/")
async def root():
    return {"message": "EventMaster API is running"}

@app.get("/api/check-mailru-config")
async def check_mailru_config():
    return {
        "MAILRU_CLIENT_ID": "Установлен" if MAILRU_CLIENT_ID else "Не установлен",
        "MAILRU_CLIENT_SECRET": "Установлен" if MAILRU_CLIENT_SECRET else "Не установлен"
    }
        
@app.get("/api/check-db")
async def check_db(db: Session = Depends(get_db)):
    try:
        db.execute("SELECT 1")
        tables = db.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'").fetchall()
        users_columns = db.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users'").fetchall()
        return {
            "status": "OK",
            "tables": [t[0] for t in tables],
            "users_columns": [c[0] for c in users_columns]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
@app.post("/api/auth/refresh")
async def refresh_token(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            raise HTTPException(status_code=401, detail="Invalid user")
            
        return {
            "access_token": create_access_token({"sub": username}),
            "token_type": "bearer"
        }
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Роуты аутентификации
@app.post("/api/auth/signup")
async def signup(user: UserCreate, db = Depends(get_db)):
    # Проверяем, существует ли пользователь
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    try:
        print("Регистрация:", user.dict()) 
        db_user = User(
            username=user.username,
            email=user.email,
            hashed_password=get_password_hash(user.password)
        )
        db.add(db_user)
        db.commit()
        return {
            "access_token": create_access_token({"sub": user.username}),
            "token_type": "bearer",
            "user": db_user  # Добавляем пользователя в ответ
        }
    except Exception as e:
        print(f"Ошибка регистрации: {str(e)}")  # Логи в консоль сервера
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/login", response_model=Token)
async def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    return {
        "access_token": create_access_token({"sub": user.username}),
        "token_type": "bearer"
    }

# Mail.ru OAuth endpoint (updated)
@app.post("/api/auth/mailru", response_model=Token)
async def mailru_auth(code: str, state: str, auth_data: MailruAuthRequest, db: Session = Depends(get_db)):
    if not state:
        raise HTTPException(status_code=400, detail="State parameter missing")

    if not MAILRU_CLIENT_ID or not MAILRU_CLIENT_SECRET:
        logger.error("Mail.ru OAuth не настроен: отсутствуют client_id или client_secret")
        raise HTTPException(
            status_code=500,
            detail="OAuth authentication not configured"
        )

    try:
        # Получаем токен
        token_response = requests.post(
            MAILRU_TOKEN_URL,
            data={
                "client_id": MAILRU_CLIENT_ID,
                "client_secret": MAILRU_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": auth_data.code,
                "redirect_uri": "https://table-games.netlify.app/api/auth/mailru/callback"  # Добавьте ваш URL
            }
        )
        token_response.raise_for_status()
        token_data = token_response.json()

        # Получаем информацию о пользователе
        user_info = requests.get(
            MAILRU_API_URL,
            params={"access_token": token_data["access_token"]}
        ).json()

        # Поиск или создание пользователя
        user = db.query(User).filter(User.mailru_id == user_info["email"]).first()
        if not user:
            user = User(
                username=f"mailru_{user_info['email'].split('@')[0]}",
                email=user_info["email"],
                mailru_id=user_info["email"],
                is_active=True
            )
            db.add(user)
            db.commit()

        return {
            "access_token": create_access_token({"sub": user.username}),
            "token_type": "bearer"
        }

    except Exception as e:
        logger.error(f"Ошибка OAuth Mail.ru: {str(e)}")
        raise HTTPException(status_code=400, detail="OAuth authentication failed")

# Игровые роуты (полностью сохранены из вашего оригинального кода)
@app.get("/api/users/me", response_model=UserInDB)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.put("/api/users/me", response_model=UserInDB)
async def update_user_me(update_data: UserBase, current_user: User = Depends(get_current_user), db = Depends(get_db)):
    try:
        for var, value in update_data.dict().items():
            setattr(current_user, var, value)
        db.commit()
        return current_user
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/games", response_model=List[GameInDB])
async def get_games(status: Optional[str] = None, creator_id: Optional[str] = None, db = Depends(get_db)):
    query = db.query(Game)
    if status: query = query.filter(Game.status == status)
    if creator_id: query = query.filter(Game.creator_id == creator_id)
    return query.all()

@app.post("/api/games", response_model=GameInDB)
async def create_game(game: GameBase, current_user: User = Depends(get_current_user), db = Depends(get_db)):
    db_game = Game(**game.dict(), creator_id=current_user.id)
    db.add(db_game)
    
    association = PlayerGameAssociation(player_id=current_user.id, game_id=db_game.id)
    db.add(association)
    db_game.current_players = 1
    
    try:
        db.commit()
        return db_game
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/games/{game_id}/join")
async def join_game(game_id: str, current_user: User = Depends(get_current_user), db = Depends(get_db)):
    game = db.query(Game).get(game_id)
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    
    if game.current_players >= game.max_players:
        raise HTTPException(status_code=400, detail="Game is full")
    
    if db.query(PlayerGameAssociation).filter_by(player_id=current_user.id, game_id=game_id).first():
        raise HTTPException(status_code=400, detail="Already joined")
    
    db.add(PlayerGameAssociation(player_id=current_user.id, game_id=game_id))
    game.current_players += 1
    
    try:
        db.commit()
        return {"message": "Joined successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/games/{game_id}")
async def delete_game(game_id: str, current_user: User = Depends(get_current_user), db = Depends(get_db)):
    game = db.query(Game).get(game_id)
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    
    if game.creator_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your game")
    
    try:
        db.query(PlayerGameAssociation).filter_by(game_id=game_id).delete()
        db.delete(game)
        db.commit()
        return {"message": "Game deleted"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__": 
    reset_database() #вывод при запуске
    create_tables()  # Сначала создаем таблицы

    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
