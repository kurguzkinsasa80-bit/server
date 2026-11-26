import os, time, psycopg2, hashlib, secrets
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Получаем ссылку на базу данных из настроек Render
DATABASE_URL = os.environ.get("DATABASE_URL")
PRIV_PATH = "private.key"
PUB_PATH = "public.key"

def init_keys():
    if not os.path.exists(PRIV_PATH):
        k = Ed25519PrivateKey.generate()
        open(PRIV_PATH, "wb").write(k.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        open(PUB_PATH, "wb").write(k.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))

def db():
    # Подключаемся к PostgreSQL
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cur = conn.cursor()
    
    # Создаем таблицы, если их нет
    cur.execute("""CREATE TABLE IF NOT EXISTS licenses(
        key_hash TEXT PRIMARY KEY, hwid TEXT,
        expires_at BIGINT, banned INTEGER DEFAULT 0, created_at BIGINT,
        user_id BIGINT)""")
        
    try:
        cur.execute("ALTER TABLE licenses ADD COLUMN user_id BIGINT")
        conn.commit()
    except psycopg2.errors.DuplicateColumn:
        conn.rollback() # Колонка уже существует
        
    cur.execute("""CREATE TABLE IF NOT EXISTS used_nonces(
        nonce TEXT PRIMARY KEY, ts BIGINT)""")
        
    cur.execute("""CREATE TABLE IF NOT EXISTS bot_settings(
        name TEXT PRIMARY KEY, value TEXT)""")
    cur.execute("INSERT INTO bot_settings (name, value) VALUES ('channel', '@powerchams') ON CONFLICT (name) DO NOTHING")
    
    conn.commit()
    return conn, cur

def load_priv():
    return Ed25519PrivateKey.from_private_bytes(open(PRIV_PATH, "rb").read())

init_keys()
app = FastAPI()

class VerifyReq(BaseModel):
    key: str
    hwid: str
    nonce: str

@app.post("/verify")
def verify(req: VerifyReq):
    conn, cur = db()
    kh = hashlib.sha256(req.key.encode()).hexdigest()
    
    # Ищем ключ в базе
    cur.execute("SELECT hwid, expires_at, banned FROM licenses WHERE key_hash = %s", (kh,))
    row = cur.fetchone()
    
    if not row: 
        conn.close()
        raise HTTPException(401, "invalid")
        
    hwid, exp, banned = row
    if banned: 
        conn.close()
        raise HTTPException(403, "banned")
        
    now = int(time.time())
    if exp and exp < now: 
        conn.close()
        raise HTTPException(403, "expired")
        
    # Если HWID пустой, привязываем
    if hwid is None:
        cur.execute("UPDATE licenses SET hwid = %s WHERE key_hash = %s", (req.hwid, kh))
        conn.commit()
        hwid = req.hwid
    elif hwid != req.hwid:
        conn.close()
        raise HTTPException(403, "hwid_mismatch")

    # Защита от повторного использования nonce
    cur.execute("SELECT 1 FROM used_nonces WHERE nonce = %s", (req.nonce,))
    if cur.fetchone():
        conn.close()
        raise HTTPException(409, "replay")
        
    cur.execute("INSERT INTO used_nonces (nonce, ts) VALUES (%s, %s)", (req.nonce, now))
    cur.execute("DELETE FROM used_nonces WHERE ts < %s", (now - 86400,))
    conn.commit()

    # Подписываем ответ
    payload = f"{req.hwid}|{exp or 0}|{now + 3600}|{req.nonce}"
    sig = load_priv().sign(payload.encode()).hex()
    conn.close()
    return {"payload": payload, "sig": sig}
