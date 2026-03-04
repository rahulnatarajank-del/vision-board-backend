from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
import sqlite3
import bcrypt
import httpx
import json
import asyncio
from urllib.parse import quote
import base64
import os
from openai import OpenAI

# CONFIG
SECRET_KEY = "change-this-secret-key-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 12
DB_PATH = "visionboard.db"

app = FastAPI(title="Women's Day Vision Board API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:3000",
    "https://womensdayvisionboard.netlify.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer()


# DATABASE
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            is_first_login INTEGER DEFAULT 1,
            attempts_remaining INTEGER DEFAULT 5,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vision_boards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT,
            form_data TEXT,
            image_urls TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()
    print("Database ready")


init_db()


# HELPERS
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired, please login again")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# SCHEMAS
class LoginRequest(BaseModel):
    email: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class CreateUserRequest(BaseModel):
    name: str
    email: str
    initial_password: str


# AUTH ROUTES
@app.post("/auth/login")
def login(request: LoginRequest):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (request.email,)).fetchone()
    conn.close()

    if not user or not verify_password(request.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"user_id": user["id"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "is_first_login": bool(user["is_first_login"]),
            "attempts_remaining": user["attempts_remaining"],
        }
    }


@app.post("/auth/change-password")
def change_password(request: ChangePasswordRequest, user_id: int = Depends(get_current_user)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not verify_password(request.current_password, user["hashed_password"]):
        conn.close()
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    conn.execute(
        "UPDATE users SET hashed_password = ?, is_first_login = 0 WHERE id = ?",
        (hash_password(request.new_password), user_id)
    )
    conn.commit()
    conn.close()
    return {"message": "Password changed successfully"}


@app.get("/auth/me")
def get_me(user_id: int = Depends(get_current_user)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "is_first_login": bool(user["is_first_login"]),
        "attempts_remaining": user["attempts_remaining"],
    }


# ADMIN ROUTES
@app.post("/admin/create-user")
def create_user(request: CreateUserRequest):
    conn = get_db()
    if conn.execute("SELECT id FROM users WHERE email = ?", (request.email,)).fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already exists")

    conn.execute(
        "INSERT INTO users (name, email, hashed_password) VALUES (?, ?, ?)",
        (request.name, request.email, hash_password(request.initial_password))
    )
    conn.commit()
    conn.close()
    return {"message": f"User '{request.name}' created successfully"}


@app.get("/admin/users")
def list_users():
    conn = get_db()
    users = conn.execute(
        "SELECT id, name, email, is_first_login, attempts_remaining, created_at FROM users"
    ).fetchall()
    conn.close()
    return [dict(u) for u in users]


@app.delete("/admin/delete-user/{user_id}")
def delete_user(user_id: int):
    conn = get_db()
    user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    conn.execute("DELETE FROM vision_boards WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"User {user_id} deleted successfully"}


# VISION BOARD ROUTES
@app.get("/boards/my-boards")
def get_my_boards(user_id: int = Depends(get_current_user)):
    conn = get_db()
    boards = conn.execute(
        "SELECT * FROM vision_boards WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(b) for b in boards]


# ── THIS FUNCTION MUST BE OUTSIDE AND ABOVE generate_board ──
async def fetch_image_as_base64(index: int) -> str:
    url = f"https://picsum.photos/seed/{index + 100}/512/512"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, follow_redirects=True)
            if response.status_code == 200:
                image_data = base64.b64encode(response.content).decode("utf-8")
                return f"data:image/jpeg;base64,{image_data}"
            else:
                print(f"Failed image {index}: status {response.status_code}")
                return ""
    except Exception as e:
        print(f"Error fetching image {index}: {e}")
        return ""


@app.post("/boards/generate")
async def generate_board(request: Request, user_id: int = Depends(get_current_user)):
    form_data = await request.json()

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if user["attempts_remaining"] <= 0:
        conn.close()
        raise HTTPException(status_code=400, detail="No attempts remaining")

    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    name = user["name"].split()[0]

    # Step 1 — GPT-4o mini generates a rich prompt
    prompt_messages = [
        {
            "role": "system",
            "content": (
                "You are a creative vision board designer. "
                "Given a person's answers, create a detailed image generation prompt "
                "for a beautiful 3x3 vision board grid. "
                "Each panel should be clearly separated and visually distinct. "
                "Make it colorful, inspiring, feminine, and empowering. "
                "IMPORTANT: For the text labels in each panel, use very short 1-2 word labels only. "
                "Keep all text extremely simple and short to avoid spelling errors. "
                "Focus more on beautiful illustrations and less on text inside the image. "
                "Return ONLY the image prompt, nothing else."
            )
        },
        {
            "role": "user",
            "content": f"""Create a vision board image prompt for {name} with these 9 panels in a 3x3 grid:

Panel 1 (top-left): Skill to master - {form_data.get('skill', '')}
Panel 2 (top-center): Dream role - {form_data.get('role', '')}
Panel 3 (top-right): Top strengths - {form_data.get('strengths', '')}
Panel 4 (mid-left): Core values - {form_data.get('values', '')}
Panel 5 (mid-center): Dream place - {form_data.get('place', '')}
Panel 6 (mid-right): Superpower at work - {form_data.get('superpower', '')}
Panel 7 (bottom-left): Outside work goal - {form_data.get('outside_work', '')}
Panel 8 (bottom-center): Cause/mission - {form_data.get('cause', '')}
Panel 9 (bottom-right): Message to future self - {form_data.get('future_self', '')}

Make it a single cohesive 3x3 grid image. Each panel beautifully illustrated, 
with a small label at the bottom of each panel. Warm, feminine, inspiring colors.
Perfect for a Women's Day vision board."""
        }
    ]

    text_response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=prompt_messages,
        max_tokens=500
    )
    image_prompt = text_response.choices[0].message.content
    print(f"Generated prompt: {image_prompt}")

    # Step 2 — GPT Image 1 generates the vision board
    image_response = client.images.generate(
        model="gpt-image-1",
        prompt=image_prompt,
        size="1024x1024",
        quality="medium",
        n=1,
    )

    # GPT Image 1 returns base64
    image_base64 = image_response.data[0].b64_json
    image_url = f"data:image/png;base64,{image_base64}"

    print("Vision board image generated successfully!")

    # Save board to database
    title = f"{user['name']}'s Vision Board"
    conn.execute(
        "INSERT INTO vision_boards (user_id, title, form_data, image_urls) VALUES (?, ?, ?, ?)",
        (user_id, title, json.dumps(form_data), json.dumps([image_url]))
    )

    # Decrease attempts
    conn.execute(
        "UPDATE users SET attempts_remaining = attempts_remaining - 1 WHERE id = ?",
        (user_id,)
    )
    conn.commit()

    updated_user = conn.execute(
        "SELECT attempts_remaining FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()

    return {
        "title": title,
        "image_urls": [image_url],
        "attempts_remaining": updated_user["attempts_remaining"],
        "form_data": form_data,
    }

@app.get("/")
def root():
    return {"message": "Women's Day Vision Board API is running!"}