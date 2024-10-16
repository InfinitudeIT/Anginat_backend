import uuid
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Column, String, Boolean, Date, ForeignKey, LargeBinary, Enum as SQLAlchemyEnum, Integer
from sqlalchemy.orm import relationship
from database import Base
from schemas import EventStatusEnum
from sqlalchemy.dialects.postgresql import JSONB


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String, nullable=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    is_restricted = Column(Boolean, default=False)
    create_event = Column(Boolean, default=True)
    create_form = Column(Boolean, default=True)
    view_registrations = Column(Boolean, default=False)

    events = relationship("Event", back_populates="owner")

class Event(Base):
    __tablename__ = "events"
    __table_args__ = {'extend_existing': True}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    event_name = Column(String, index=True)
    venue_address = Column(String)
    event_date = Column(Date)
    audience = Column(Boolean, default=False)
    delegates = Column(Boolean, default=False)
    speaker = Column(Boolean, default=False)
    nri = Column(Boolean, default=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    status = Column(SQLAlchemyEnum(EventStatusEnum), default=EventStatusEnum.PENDING)

    owner = relationship("User", back_populates="events")
    forms = relationship("EventForm", back_populates="event", cascade="all, delete-orphan")
    image = relationship("ImageModel", back_populates="event", uselist=False, cascade="all, delete-orphan")

class EventForm(Base):
    __tablename__ = "event_forms"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"), nullable=False)
    form_data = Column(JSONB, nullable=False)  # Store form fields and their values
    qr_code = Column(LargeBinary)  # Store generated QR code if needed

    event = relationship("Event", back_populates="forms")

class ImageModel(Base):
    __tablename__ = "images"

    id = Column(Integer, primary_key=True)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"), unique=True, nullable=False)
    filename = Column(String, nullable=False)
    data = Column(LargeBinary, nullable=False)

    event = relationship("Event", back_populates="image")