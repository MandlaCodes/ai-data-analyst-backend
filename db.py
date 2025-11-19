import os
import json
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import declarative_base, sessionmaker

# ---------------------------
# Paths and Engine
# ---------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "tokens.db")  # SQLite file in project root

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False}  # Required for SQLite + FastAPI
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ---------------------------
# Token Table
# ---------------------------
class Token(Base):
    __tablename__ = "tokens"
    user_id = Column(String, primary_key=True, index=True)
    token_data = Column(String)

# Create tables automatically if they don't exist
Base.metadata.create_all(engine)

# ---------------------------
# Helper functions
# ---------------------------
def save_token(user_id, token_data):
    session = SessionLocal()
    token_json = json.dumps(token_data)
    token = session.query(Token).filter(Token.user_id == user_id).first()
    if token:
        token.token_data = token_json
    else:
        token = Token(user_id=user_id, token_data=token_json)
        session.add(token)
    session.commit()
    session.close()

def get_token(user_id):
    session = SessionLocal()
    token = session.query(Token).filter(Token.user_id == user_id).first()
    session.close()
    if token:
        return json.loads(token.token_data)
    return None

def delete_token(user_id):
    session = SessionLocal()
    token = session.query(Token).filter(Token.user_id == user_id).first()
    if token:
        session.delete(token)
        session.commit()
    session.close()
