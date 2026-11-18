import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings

connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """FastAPI Dependency yielding scoped SQLAlchemy Session."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def seed_default_admin():
    """Seeds default administrator account and tenant if not already present."""
    from app.core.security import hash_password
    from app.models.tenant import Tenant
    from app.models.user import User

    db: Session = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.name == "Provilance Technologies").first()
        if not tenant:
            tenant = Tenant(name="Provilance Technologies")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)

        admin = db.query(User).filter(User.email == "admin@aegisai.com").first()
        if not admin:
            admin = User(
                tenant_id=tenant.id,
                email="admin@aegisai.com",
                hashed_password=hash_password("admin123"),
                role="admin",
                is_active=True
            )
            db.add(admin)
            db.commit()
    except Exception:
        pass
    finally:
        db.close()

def init_db():
    """Create all registered database tables and seed default admin."""
    Base.metadata.create_all(bind=engine)
    seed_default_admin()
