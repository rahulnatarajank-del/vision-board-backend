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
import json
import io
from PIL import Image

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
            attempts_remaining INTEGER DEFAULT 3,
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
# --- HELPER: Logic for individual panel generation ---
async def fetch_panel(client, topic, name):
    # Short, focused prompt for better DALL-E 2 results
    prompt = (
        f"A dreamy cinematic digital art illustration of {topic} for {name}. "
        "Style: Indian feminine aesthetic, soft lighting, rose gold and peach tones, "
        "highly detailed, NO text, NO words."
    )
    # DALL-E 2 (512x512) is ~$0.018 per image
    response = await asyncio.to_thread(
        client.images.generate,
        model="dall-e-2",
        prompt=prompt,
        n=1,
        size="512x512",
        response_format="b64_json"
    )
    return response.data[0].b64_json

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

    # Map your 9 questions to a list
    keys = ['skill', 'role', 'strengths', 'values', 'place', 'superpower', 'outside_work', 'cause', 'future_self']
    topics = [form_data.get(k, "My Future") for k in keys]

    try:
        # Fire all 9 requests at once (Parallel)
        tasks = [fetch_panel(client, t, name) for t in topics]
        image_b64s = await asyncio.gather(*tasks)
        
        # Stitch them together
        images = [Image.open(io.BytesIO(base64.b64decode(b64))) for b64 in image_b64s]
        
        # 3x3 Grid (Each cell is 512px, Total 1536px)
        grid_size = 512 * 3
        final_grid = Image.new('RGB', (grid_size, grid_size), color=(255, 245, 240)) # Peach background

        for i, img in enumerate(images):
            x = (i % 3) * 512
            y = (i // 3) * 512
            final_grid.paste(img, (x, y))

        # Convert to final Base64
        buffered = io.BytesIO()
        final_grid.save(buffered, format="JPEG", quality=85)
        image_url = f"data:image/jpeg;base64,{base64.b64encode(buffered.getvalue()).decode()}"

    except Exception as e:
        print(f"Error: {e}")
        conn.close()
        raise HTTPException(status_code=500, detail="Vision Board generation failed. Please try again.")

    # Save to database
    title = f"{user['name']}'s Vision Board"
    conn.execute(
        "INSERT INTO vision_boards (user_id, title, form_data, image_urls) VALUES (?, ?, ?, ?)",
        (user_id, title, json.dumps(form_data), json.dumps([image_url]))
    )
    conn.execute("UPDATE users SET attempts_remaining = attempts_remaining - 1 WHERE id = ?", (user_id,))
    conn.commit()
    
    updated_user = conn.execute("SELECT attempts_remaining FROM users WHERE id = ?", (user_id,)).fetchone()
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