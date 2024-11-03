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
    lunch = Column(Boolean, default=False)
    kit = Column(Boolean, default=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    status = Column(SQLAlchemyEnum(EventStatusEnum), default=EventStatusEnum.APPROVED)

    owner = relationship("User", back_populates="events")
    forms = relationship("EventForm", back_populates="event", cascade="all, delete-orphan")
    


class EventForm(Base):
    __tablename__ = "event_forms"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"), nullable=False)
    form_name = Column(String, nullable=False)
    form_data = Column(JSONB, nullable=False)  # Dynamic form structure

    event = relationship("Event", back_populates="forms")  # Ensure this exists
    submissions = relationship("EventFormSubmission", back_populates="form")



from sqlalchemy import Boolean

class EventFormSubmission(Base):
    __tablename__ = "event_form_submissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    form_id = Column(UUID(as_uuid=True), ForeignKey("event_forms.id"), nullable=False)
    submission_data = Column(JSONB, nullable=False)  # Store user-submitted data
    mode = Column(String)
    qr_code = Column(LargeBinary)  # Store the QR code as binary data
    lunch = Column(Boolean, default=False)  # New column for lunch eligibility
    kit = Column(Boolean, default=False)    # New column for kit eligibility

    form = relationship("EventForm", back_populates="submissions")


class IDCardFields(Base):
    __tablename__ = "id_card_fields"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    form_id = Column(UUID(as_uuid=True), ForeignKey("event_forms.id"), nullable=False)
    selected_fields = Column(JSONB, nullable=False)  # Stores selected fields for the ID card
    custom_layout = Column(JSONB, nullable=True)     # Optional custom layout for ID card fields
    photo = Column(LargeBinary, nullable=True)      # Store photo as binary data

    form = relationship("EventForm", back_populates="id_card_fields")