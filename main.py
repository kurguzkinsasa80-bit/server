import os, time, sqlite3, hashlib, secrets
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

DB = "keys.db"
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
    c = sqlite3.connect(DB)
    # Создаем таблицу с user_id
    c.execute("""CREATE TABLE IF NOT EXISTS licenses(
        key_hash TEXT PRIMARY KEY, hwid TEXT,
        expires_at INTEGER, banned INTEGER DEFAULT 0, created_at INTEGER,
        user_id INTEGER)""")
        
    # МИГРАЦИЯ: Если база старая (без user_id), добавляем колонку
    try:
        c.execute("ALTER TABLE licenses ADD COLUMN user_id INTEGER")
    except sqlite3.OperationalError:
        pass # Колонка уже существует
        
    c.execute("""CREATE TABLE IF NOT EXISTS used_nonces(
        nonce TEXT PRIMARY KEY, ts INTEGER)""")
        
    # Таблица настроек бота (канал)
    c.execute("""CREATE TABLE IF NOT EXISTS bot_settings(
        name TEXT PRIMARY KEY, value TEXT)""")
    c.execute("INSERT OR IGNORE INTO bot_settings (name, value) VALUES ('channel', '@powerchams')")
    
    return c

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
    c = db(); cur = c.cursor()
    kh = hashlib.sha256(req.key.encode()).hexdigest()
    row = cur.execute("SELECT hwid,expires_at,banned FROM licenses WHERE key_hash=?", (kh,)).fetchone()
    if not row: raise HTTPException(401, "invalid")
    hwid, exp, banned = row
    if banned: raise HTTPException(403, "banned")
    now = int(time.time())
    if exp and exp < now: raise HTTPException(403, "expired")
    if hwid is None:
        cur.execute("UPDATE licenses SET hwid=? WHERE key_hash=?", (req.hwid, kh)); c.commit()
        hwid = req.hwid
    elif hwid != req.hwid:
        raise HTTPException(403, "hwid_mismatch")

    if cur.execute("SELECT 1 FROM used_nonces WHERE nonce=?", (req.nonce,)).fetchone():
        raise HTTPException(409, "replay")
    cur.execute("INSERT INTO used_nonces VALUES(?,?)", (req.nonce, now))
    cur.execute("DELETE FROM used_nonces WHERE ts < ?", (now - 86400,))
    c.commit()

    payload = f"{req.hwid}|{exp or 0}|{now + 3600}|{req.nonce}"
    sig = load_priv().sign(payload.encode()).hex()
    return {"payload": payload, "sig": sig}