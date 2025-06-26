from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List, Dict
import os
from enum import Enum

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:Ranjanitech%40123@localhost:5432/feedback_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# FastAPI app
app = FastAPI(title="Feedback System API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Enums
class UserRole(str, Enum):
    MANAGER = "manager"
    EMPLOYEE = "employee"

class SentimentType(str, Enum):
    POSITIVE = "positive"
    NEUTRAL = "neutral"  
    NEGATIVE = "negative"

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)
    manager_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    manager = relationship("User", remote_side=[id])
    feedback_given = relationship("Feedback", foreign_keys="Feedback.manager_id", back_populates="manager")
    feedback_received = relationship("Feedback", foreign_keys="Feedback.employee_id", back_populates="employee")

class Feedback(Base):
    __tablename__ = "feedback"
    
    id = Column(Integer, primary_key=True, index=True)
    manager_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    employee_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    strengths = Column(Text, nullable=False)
    areas_to_improve = Column(Text, nullable=False)
    sentiment = Column(String, nullable=False)
    is_acknowledged = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    manager = relationship("User", foreign_keys=[manager_id], back_populates="feedback_given")
    employee = relationship("User", foreign_keys=[employee_id], back_populates="feedback_received")

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: UserRole
    manager_id: Optional[int] = None

class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    role: str
    manager_id: Optional[int] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    access_token: str
    user: UserResponse

class FeedbackCreate(BaseModel):
    employee_id: int
    strengths: str
    areas_to_improve: str
    sentiment: SentimentType

class FeedbackUpdate(BaseModel):
    strengths: Optional[str] = None
    areas_to_improve: Optional[str] = None
    sentiment: Optional[SentimentType] = None

class FeedbackResponse(BaseModel):
    id: int
    manager_id: int
    employee_id: int
    manager_name: str
    employee_name: str
    strengths: str
    areas_to_improve: str
    sentiment: str
    is_acknowledged: bool
    created_at: datetime
    updated_at: datetime

class DashboardStats(BaseModel):
    total_feedback: int
    pending_acknowledgments: int
    sentiment_breakdown: Dict[str, int]

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Authentication utilities
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
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# Initialize demo data
def init_demo_data(db: Session):
    # Check if users already exist
    if db.query(User).first():
        return
    
    # Create demo manager
    manager = User(
        email="manager@company.com",
        name="John Manager",
        password_hash=get_password_hash("password123"),
        role=UserRole.MANAGER.value
    )
    db.add(manager)
    db.commit()
    db.refresh(manager)
    
    # Create demo employee
    employee = User(
        email="employee@company.com",
        name="Jane Employee",
        password_hash=get_password_hash("password123"),
        role=UserRole.EMPLOYEE.value,
        manager_id=manager.id
    )
    db.add(employee)
    db.commit()
    db.refresh(employee)
    
    # Create demo feedback
    feedback = Feedback(
        manager_id=manager.id,
        employee_id=employee.id,
        strengths="Excellent communication skills and always meets deadlines. Shows great initiative in problem-solving.",
        areas_to_improve="Could benefit from more technical training in the new frameworks we're adopting.",
        sentiment=SentimentType.POSITIVE.value
    )
    db.add(feedback)
    db.commit()

# Initialize demo data on startup
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        init_demo_data(db)
    finally:
        db.close()

# API Routes
@app.post("/auth/login", response_model=LoginResponse)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    return LoginResponse(
        access_token=access_token,
        user=UserResponse(
            id=user.id,
            email=user.email,
            name=user.name,
            role=user.role,
            manager_id=user.manager_id
        )
    )

@app.get("/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        name=current_user.name,
        role=current_user.role,
        manager_id=current_user.manager_id
    )

@app.get("/users/team", response_model=List[UserResponse])
def get_team_members(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != UserRole.MANAGER.value:
        raise HTTPException(status_code=403, detail="Only managers can access team members")
    
    team_members = db.query(User).filter(User.manager_id == current_user.id).all()
    return [UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        manager_id=user.manager_id
    ) for user in team_members]

@app.post("/feedback", response_model=FeedbackResponse)
def create_feedback(feedback_data: FeedbackCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != UserRole.MANAGER.value:
        raise HTTPException(status_code=403, detail="Only managers can create feedback")
    
    # Verify the employee is in the manager's team
    employee = db.query(User).filter(User.id == feedback_data.employee_id, User.manager_id == current_user.id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found in your team")
    
    feedback = Feedback(
        manager_id=current_user.id,
        employee_id=feedback_data.employee_id,
        strengths=feedback_data.strengths,
        areas_to_improve=feedback_data.areas_to_improve,
        sentiment=feedback_data.sentiment.value
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    
    return FeedbackResponse(
        id=feedback.id,
        manager_id=feedback.manager_id,
        employee_id=feedback.employee_id,
        manager_name=current_user.name,
        employee_name=employee.name,
        strengths=feedback.strengths,
        areas_to_improve=feedback.areas_to_improve,
        sentiment=feedback.sentiment,
        is_acknowledged=feedback.is_acknowledged,
        created_at=feedback.created_at,
        updated_at=feedback.updated_at
    )

@app.get("/feedback", response_model=List[FeedbackResponse])
def get_feedback(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == UserRole.MANAGER.value:
        # Managers see feedback they've given
        feedback_list = db.query(Feedback).filter(Feedback.manager_id == current_user.id).all()
    else:
        # Employees see feedback they've received
        feedback_list = db.query(Feedback).filter(Feedback.employee_id == current_user.id).all()
    
    result = []
    for feedback in feedback_list:
        manager = db.query(User).filter(User.id == feedback.manager_id).first()
        employee = db.query(User).filter(User.id == feedback.employee_id).first()
        
        result.append(FeedbackResponse(
            id=feedback.id,
            manager_id=feedback.manager_id,
            employee_id=feedback.employee_id,
            manager_name=manager.name if manager else "Unknown",
            employee_name=employee.name if employee else "Unknown",
            strengths=feedback.strengths,
            areas_to_improve=feedback.areas_to_improve,
            sentiment=feedback.sentiment,
            is_acknowledged=feedback.is_acknowledged,
            created_at=feedback.created_at,
            updated_at=feedback.updated_at
        ))
    
    return sorted(result, key=lambda x: x.created_at, reverse=True)

@app.get("/feedback/{feedback_id}", response_model=FeedbackResponse)
def get_feedback_by_id(feedback_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    feedback = db.query(Feedback).filter(Feedback.id == feedback_id).first()
    if not feedback:
        raise HTTPException(status_code=404, detail="Feedback not found")
    
    # Check permissions
    if current_user.role == UserRole.MANAGER.value and feedback.manager_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    elif current_user.role == UserRole.EMPLOYEE.value and feedback.employee_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    manager = db.query(User).filter(User.id == feedback.manager_id).first()
    employee = db.query(User).filter(User.id == feedback.employee_id).first()
    
    return FeedbackResponse(
        id=feedback.id,
        manager_id=feedback.manager_id,
        employee_id=feedback.employee_id,
        manager_name=manager.name if manager else "Unknown",
        employee_name=employee.name if employee else "Unknown",
        strengths=feedback.strengths,
        areas_to_improve=feedback.areas_to_improve,
        sentiment=feedback.sentiment,
        is_acknowledged=feedback.is_acknowledged,
        created_at=feedback.created_at,
        updated_at=feedback.updated_at
    )

@app.put("/feedback/{feedback_id}", response_model=FeedbackResponse)
def update_feedback(feedback_id: int, feedback_data: FeedbackUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != UserRole.MANAGER.value:
        raise HTTPException(status_code=403, detail="Only managers can update feedback")
    
    feedback = db.query(Feedback).filter(Feedback.id == feedback_id, Feedback.manager_id == current_user.id).first()
    if not feedback:
        raise HTTPException(status_code=404, detail="Feedback not found")
    
    if feedback_data.strengths is not None:
        feedback.strengths = feedback_data.strengths
    if feedback_data.areas_to_improve is not None:
        feedback.areas_to_improve = feedback_data.areas_to_improve
    if feedback_data.sentiment is not None:
        feedback.sentiment = feedback_data.sentiment.value
    
    feedback.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(feedback)
    
    manager = db.query(User).filter(User.id == feedback.manager_id).first()
    employee = db.query(User).filter(User.id == feedback.employee_id).first()
    
    return FeedbackResponse(
        id=feedback.id,
        manager_id=feedback.manager_id,
        employee_id=feedback.employee_id,
        manager_name=manager.name if manager else "Unknown",
        employee_name=employee.name if employee else "Unknown",
        strengths=feedback.strengths,
        areas_to_improve=feedback.areas_to_improve,
        sentiment=feedback.sentiment,
        is_acknowledged=feedback.is_acknowledged,
        created_at=feedback.created_at,
        updated_at=feedback.updated_at
    )

@app.patch("/feedback/{feedback_id}/acknowledge")
def acknowledge_feedback(feedback_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != UserRole.EMPLOYEE.value:
        raise HTTPException(status_code=403, detail="Only employees can acknowledge feedback")
    
    feedback = db.query(Feedback).filter(Feedback.id == feedback_id, Feedback.employee_id == current_user.id).first()
    if not feedback:
        raise HTTPException(status_code=404, detail="Feedback not found")
    
    feedback.is_acknowledged = True
    feedback.updated_at = datetime.utcnow()
    db.commit()
    
    return {"message": "Feedback acknowledged successfully"}

@app.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != UserRole.MANAGER.value:
        raise HTTPException(status_code=403, detail="Only managers can access dashboard stats")
    
    feedback_list = db.query(Feedback).filter(Feedback.manager_id == current_user.id).all()
    
    total_feedback = len(feedback_list)
    pending_acknowledgments = len([f for f in feedback_list if not f.is_acknowledged])
    
    sentiment_breakdown = {
        "positive": len([f for f in feedback_list if f.sentiment == SentimentType.POSITIVE.value]),
        "neutral": len([f for f in feedback_list if f.sentiment == SentimentType.NEUTRAL.value]),
        "negative": len([f for f in feedback_list if f.sentiment == SentimentType.NEGATIVE.value])
    }
    
    return DashboardStats(
        total_feedback=total_feedback,
        pending_acknowledgments=pending_acknowledgments,
        sentiment_breakdown=sentiment_breakdown
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)