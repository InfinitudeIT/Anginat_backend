from fastapi import FastAPI, Form, Request, Depends, HTTPException, BackgroundTasks, UploadFile, File, Path
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.orm import relationship
from pydantic import BaseModel, EmailStr, constr
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from starlette.middleware.sessions import SessionMiddleware
from itsdangerous import URLSafeTimedSerializer
from database import SessionLocal, engine
from models import User, Event, EventForm, ImageModel,Date
from schemas import UserSchema, EventFormCreate, UserDetails, ImageCreate, ImageResponse, ImageBase, EventCreate
from database import Base
from datetime import date
from schemas import EventStatusEnum
import base64
from typing import List, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from jinja2 import Template
from starlette.status import HTTP_401_UNAUTHORIZED
from functools import wraps
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from datetime import datetime, timedelta
import qrcode
from io import BytesIO
import json
import os
from uuid import UUID, uuid4
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Form
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi import FastAPI, Request, Depends, Form
from sqlalchemy.orm import Session
from pydantic import BaseModel
from starlette.responses import JSONResponse
from sqlalchemy import select


app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key="b436b7880fc6857423bb4be8")

templates = Jinja2Templates(directory="templates")

Base.metadata.create_all(bind=engine)

serializer = URLSafeTimedSerializer("b436b7880fc6857423bb4be8")

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class EmailSettings(BaseModel):
    MAIL_USERNAME: EmailStr
    MAIL_PASSWORD: constr(min_length=1)
    MAIL_PORT: int
    MAIL_SERVER: str
    MAIL_FROM: EmailStr
    MAIL_STARTTLS: bool
    MAIL_SSL_TLS: bool
    USE_CREDENTIALS: bool
    VALIDATE_CERTS: bool


email_settings = EmailSettings(
    MAIL_USERNAME="gokulrengaraj07@gmail.com",
    MAIL_PASSWORD="nhlq zhsr kivr wslm",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_FROM="gokulrengaraj07@gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=False
)

conf = ConnectionConfig(
    MAIL_USERNAME=email_settings.MAIL_USERNAME,
    MAIL_PASSWORD=email_settings.MAIL_PASSWORD,
    MAIL_PORT=email_settings.MAIL_PORT,
    MAIL_SERVER=email_settings.MAIL_SERVER,
    MAIL_FROM=email_settings.MAIL_FROM,
    MAIL_STARTTLS=email_settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=email_settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=email_settings.USE_CREDENTIALS,
    VALIDATE_CERTS=email_settings.VALIDATE_CERTS
)

fm = FastMail(conf)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Allow only your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request):
    user_email = request.session.get('user_email')
    if not user_email:
        raise HTTPException(status_code=403, detail="Not authenticated")
    return user_email


def get_current_admin(request: Request):
    admin = request.session.get('admin')
    if not admin:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return admin

def require_admin(func):
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        try:
            get_current_admin(request)
            if not request.session.get('authenticated'):
                raise HTTPException(status_code=401, detail="Not authenticated")
        except HTTPException:
            return RedirectResponse(url="/admin-login", status_code=303)
        return await func(request, *args, **kwargs)

    return wrapper


def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

def generate_qr_code(data: dict, file_path: str):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img.save(file_path)


@app.get("/", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})



class UserRegisterRequest(BaseModel):
    email: str
    password: str

@app.post("/register", response_class=JSONResponse)
async def register_post(user: UserRegisterRequest, db: Session = Depends(get_db)):
    try:
        # Check if the user already exists
        existing_user = db.query(User).filter(User.email == user.email).first()
        if existing_user:
            return JSONResponse(content={"success": False, "message": "Email already exists"}, status_code=400)

        # Create a new user
        unique_user_id = uuid4()
        new_user = User(
            id=unique_user_id,
            email=user.email,
            password=user.password,
            is_restricted=False,
            create_event=True,
            create_form=True
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return JSONResponse(content={"success": True, "user_id": str(unique_user_id), "message": "Registration successful"}, status_code=201)

    except Exception as e:
        db.rollback()
        return JSONResponse(content={"success": False, "message": f"An error occurred: {str(e)}"}, status_code=500)

@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


class Settings(BaseModel):
    authjwt_secret_key: str = "xxxrtoiu897678"

@AuthJWT.load_config
def get_config():
    return Settings()


# Handle JWT-related errors
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request, exc):
    return JSONResponse(status_code=401, content={"message": "Token expired or invalid."})

@app.post("/login", response_class=JSONResponse)
async def login_post(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    user = db.query(User).filter(User.email == email).first()

    if user and user.password == password and user.is_active:
        # Generate access token with user ID and permissions in payload
        access_token = Authorize.create_access_token(subject=str(user.id),
                                                     user_claims={
                                                         "permissions": {
                                                             "create_event": user.create_event,
                                                             "create_form": user.create_form,
                                                             "view_registrations": user.view_registrations
                                                         }
                                                     })
       
        # Return the token and user data
        return JSONResponse(content={
            "success": True,
            "message": "Login successful",
            "access_token": access_token,
            "user_id": str(user.id),
            "user_email": user.email,
            "permissions": {
                "create_event": user.create_event,
                "create_form": user.create_form,
                "view_registrations": user.view_registrations
            }
        })
    else:
        raise HTTPException(status_code=401, detail="Invalid email or password")




@app.get("/protected-route")
def protected_route(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()  # Validates the JWT token
   
    # Get the user ID from the token
    current_user_id = Authorize.get_jwt_subject()
   
    # Extract permissions from the token claims
    user_claims = Authorize.get_raw_jwt()
    permissions = user_claims["permissions"]
   
    return {
        "message": f"Welcome, user {current_user_id}!",
        "permissions": permissions
    }

@app.post("/create_event", response_class=JSONResponse)
async def create_event(
    event_name: str = Form(...),
    venue_address: str = Form(...),
    event_date: date = Form(...),
    audience: str = Form(...),
    delegates: str = Form(...),
    speaker: str = Form(...),
    nri: str = Form(...),
    lunch: str = Form(...),
    kit: str = Form(...),
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()  # Added to get the user ID from the token
):
    try:
        # Validate the JWT token
        Authorize.jwt_required()
        current_user_id = Authorize.get_jwt_subject()  # Get the user ID from the token

        # Convert string values to booleans
        audience = audience.lower() == 'true'
        delegates = delegates.lower() == 'true'
        speaker = speaker.lower() == 'true'
        nri = nri.lower() == 'true'
        lunch = lunch.lower() == 'true'
        kit = kit.lower() == 'true'

        # Create the new event and associate it with the current user
        new_event = Event(
            event_name=event_name,
            venue_address=venue_address,
            event_date=event_date,
            audience=audience,
            delegates=delegates,
            speaker=speaker,
            nri=nri,
            lunch = lunch,
            kit = kit,
            user_id=current_user_id,  # Associate the event with the logged-in user
            status=EventStatusEnum.APPROVED
        )

        # Add to the database session and commit
        db.add(new_event)
        db.commit()
        db.refresh(new_event)

        return JSONResponse(content={"success": True, "message": "Event created successfully", "event_id": str(new_event.id)}, status_code=201)

    except Exception as e:
        # Handle exceptions and return error response
        db.rollback()  # Rollback if there is an error
        return JSONResponse(content={"success": False, "message": f"Error creating event: {str(e)}"}, status_code=500)


@app.get("/user/{user_id}", response_class=JSONResponse)
async def get_user_details(
    user_id: UUID,
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            response_data = {
                "success": True,
                "message": "User details retrieved successfully",
                "user_id": str(user.id),
                "user_email": user.email,
                "is_active": user.is_active,
                "is_restricted": user.is_restricted,
                "permissions": {
                    "create_event": user.create_event,
                    "create_form": user.create_form,
                    "view_registrations": user.view_registrations
                }
            }
            return JSONResponse(content=response_data, status_code=200)
        else:
            return JSONResponse(content={"success": False, "message": "User not found"}, status_code=404)
    except Exception as e:
        return JSONResponse(content={"success": False, "message": f"An error occurred: {str(e)}"}, status_code=500)


@app.get("/user_events/{user_id}", response_model=List[EventCreate])
async def get_user_events(user_id: UUID, db: Session = Depends(get_db)):
    try:
        # Retrieve all events for the given user
        user_events = db.query(Event).filter(Event.user_id == user_id).all()

        # Return the events as a list of Pydantic models
        return [EventCreate.from_orm(event) for event in user_events]

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving user events: {str(e)}")


@app.post("/submit_form/{event_id}")
async def submit_form(event_id: UUID, form_data: dict, db: Session = Depends(get_db)):
    try:
        new_form = EventForm(event_id=event_id, form_data=form_data)
        db.add(new_form)
        db.commit()
        db.refresh(new_form)
        return JSONResponse(content={"success": True, "message": "Form submitted successfully.", "form_id": str(new_form.id)}, status_code=201)
    except Exception as e:
        return JSONResponse(content={"success": False, "message": f"An error occurred: {str(e)}"}, status_code=500)


@app.get("/get_forms/{event_id}")
async def get_forms(event_id: UUID, db: Session = Depends(get_db)):
    forms = db.query(EventForm).filter(EventForm.event_id == event_id).all()
    return {"forms": [form.form_data for form in forms]}



@app.put("/edit_event/{event_id}", response_class=JSONResponse)
async def edit_event(
    event_id: UUID,
    event_data: EventCreate,  # Using the same schema to validate incoming data
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    try:
        # Validate the JWT token and get the user ID
        Authorize.jwt_required()
        current_user_id = Authorize.get_jwt_subject()

        # Retrieve the event from the database
        event = db.query(Event).filter(Event.id == event_id, Event.user_id == current_user_id).first()
        if not event:
            raise HTTPException(status_code=404, detail="Event not found or unauthorized")

        # Update the event with new data
        event.event_name = event_data.event_name
        event.venue_address = event_data.venue_address
        event.event_date = event_data.event_date
        event.audience = event_data.audience
        event.delegates = event_data.delegates
        event.speaker = event_data.speaker
        event.nri = event_data.nri
        event.lunch = event_data.lunch
        event.kit = event_data.kit

        # Commit the changes to the database
        db.commit()
        db.refresh(event)

        return JSONResponse(content={"success": True, "message": "Event updated successfully"}, status_code=200)

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating event: {str(e)}")
    

@app.post("/delete_event", response_class=JSONResponse)
async def delete_event(
    event_id: str = Form(...),  # Get the event_id from form data
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    try:
        # Validate the JWT token and get the user ID
        Authorize.jwt_required()
        current_user_id = Authorize.get_jwt_subject()

        # Check if the event exists and is owned by the current user
        event = db.query(Event).filter(Event.id == event_id, Event.user_id == current_user_id).first()
        if not event:
            raise HTTPException(status_code=404, detail="Event not found or unauthorized")

        # Delete the event
        db.delete(event)
        db.commit()

        return JSONResponse(content={"success": True, "message": "Event deleted successfully"}, status_code=200)

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting event: {str(e)}")


@app.get("/event/{event_id}", response_class=JSONResponse)
async def get_event(event_id: str, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
        current_user_id = Authorize.get_jwt_subject()

        event = db.query(Event).filter(Event.id == event_id, Event.user_id == current_user_id).first()

        if not event:
            raise HTTPException(status_code=404, detail="Event not found")

        event_data = {
            "event_name": event.event_name,
            "venue_address": event.venue_address,
            "event_date": event.event_date.strftime('%Y-%m-%d'),
            "audience": event.audience,
            "delegates": event.delegates,
            "speaker": event.speaker,
            "nri": event.nri,
            "lunch": event.lunch,
            "kit": event.kit
        }

        return JSONResponse(content={"success": True, "event": event_data}, status_code=200)
    except Exception as e:
        return JSONResponse(content={"success": False, "message": str(e)}, status_code=500)


@app.post("/create_form/{event_id}")
async def create_form(event_id: UUID, form_data: dict, db: Session = Depends(get_db)):
    # Check if the event exists
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Create a new form and store its structure as JSON
    new_form = EventForm(event_id=event_id, form_data=form_data)
    db.add(new_form)
    db.commit()
    db.refresh(new_form)

    return {"success": True, "form_id": str(new_form.id), "message": "Form created successfully"}


@app.get("/generate_embed_link/{event_id}")
async def generate_embed_link(event_id: UUID):
    # Generate an embedded link using the event ID
    embed_link = f"http://localhost:3000/form/{event_id}"
    return {"success": True, "embed_link": embed_link}


@app.post("/submit_form/{event_id}")
async def submit_form(event_id: UUID, form_data: dict, db: Session = Depends(get_db)):
    try:
        # Store the submitted form data as JSON linked to the event
        new_form_submission = EventForm(event_id=event_id, form_data=form_data)
        db.add(new_form_submission)
        db.commit()
        db.refresh(new_form_submission)

        return {"success": True, "message": "Form submitted successfully"}
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}
    

