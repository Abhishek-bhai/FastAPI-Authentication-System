import os
import tempfile

os.environ.setdefault("APP_ENV", "test")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
import app.database.session as db_session
import app.main as app_main
from app.services import auth_service


@pytest.fixture(scope="function")
def client(monkeypatch):
    # Keep unit tests deterministic and independent of external SMTP credentials.
    monkeypatch.setattr(auth_service, "send_email", lambda *args, **kwargs: None)
    db_fd, db_path = tempfile.mkstemp(prefix="fastapi_auth_test_", suffix=".db", dir="/tmp")
    os.close(db_fd)
    os.unlink(db_path)

    test_db_url = f"sqlite:///{db_path}"
    os.environ["DATABASE_URL"] = test_db_url
    db_session.engine = create_engine(test_db_url, connect_args={"check_same_thread": False}, future=True)
    db_session.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_session.engine, future=True)
    app_main.engine = db_session.engine
    Base.metadata.create_all(bind=db_session.engine)
    try:
        yield TestClient(app_main.app)
    finally:
        Base.metadata.drop_all(bind=db_session.engine)
        db_session.SessionLocal().close()
        if os.path.exists(db_path):
            os.remove(db_path)
