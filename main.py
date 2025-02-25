from fastapi import FastAPI, Form, Request, Depends, HTTPException, BackgroundTasks, UploadFile, File, Path, status
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
from models import EventFormSubmission, User, Event, EventForm, IDCardFields, SubUser
from schemas import UserSchema, EventFormCreate, UserDetails, EventCreate, IDCardFieldsCreate
from database import Base
from datetime import date
from schemas import EventStatusEnum, FormCreate
import base64
from typing import Dict, List, Any, Optional
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
from fastapi import Form, Body
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
    # Function to check and return user data
    def get_user_data(email: str, password: str):
        # Check in `users` table
        user = db.query(User).filter(User.email == email).first()
        if user and user.password == password and user.is_active:
            return {
                "user": user,
                "is_subuser": False
            }

        # Check in `sub_users` table
        subuser = db.query(SubUser).filter(SubUser.email == email).first()
        if subuser and subuser.password == password:
            return {
                "user": subuser,
                "is_subuser": True
            }

        return None

    # Authenticate the user
    auth_result = get_user_data(email, password)

    if auth_result:
        user = auth_result["user"]
        is_subuser = auth_result["is_subuser"]

        # Create access token
        access_token = Authorize.create_access_token(
            subject=str(user.id),
            user_claims={
                "permissions": {
                    "create_event": user.create_event,
                    "create_form": user.create_form,
                    "view_registrations": user.view_registrations,
                },
                "is_superadmin": getattr(user, "is_superadmin", False) if not is_subuser else False,
                "is_subuser": is_subuser,
            }
        )

        # Prepare response
        return JSONResponse(content={
            "success": True,
            "message": "Login successful",
            "access_token": access_token,
            "user_id": str(user.id),
            "user_email": user.email,
            "permissions": {
                "create_event": user.create_event,
                "create_form": user.create_form,
                "view_registrations": user.view_registrations,
            },
            "is_subuser": is_subuser,
            "superadmin_logged": getattr(user, "is_superadmin", False) if not is_subuser else None,
        })

    # If no user is found or authentication fails
    raise HTTPException(status_code=401, detail="Invalid username or password")



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
            lunch=lunch,
            kit=kit,
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


@app.get("/get_forms/{event_id}")
async def get_forms(event_id: UUID, db: Session = Depends(get_db)):
    forms = db.query(EventForm).filter(EventForm.event_id == event_id).all()
    return forms


@app.put("/edit_event/{event_id}", response_class=JSONResponse)
async def edit_event(
    event_id: UUID,
    event_name: str = Form(...),
    venue_address: str = Form(...),
    event_date: str = Form(...),
    audience: bool = Form(...),
    delegates: bool = Form(...),
    speaker: bool = Form(...),
    nri: bool = Form(...),
    lunch: bool = Form(...),
    kit: bool = Form(...),
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
        event.event_name = event_name
        event.venue_address = venue_address
        event.event_date = event_date  # Convert to date if necessary
        event.audience = audience
        event.delegates = delegates
        event.speaker = speaker
        event.nri = nri
        event.lunch = lunch
        event.kit = kit

        # Commit the changes to the database
        db.commit()
        db.refresh(event)

        return JSONResponse(content={"success": True, "message": "Event updated successfully"}, status_code=200)

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating event: {str(e)}")


@app.post("/delete_event", status_code=status.HTTP_200_OK)
async def delete_event(
    event_id: str = Form(...),
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

        # Ensure related submissions are deleted to avoid foreign key constraint issues
        for form in event.forms:
            db.query(EventFormSubmission).filter(EventFormSubmission.form_id == form.id).delete()
            db.delete(form)

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


@app.get("/generate_embed_link/{event_id}")
async def generate_embed_link(event_id: UUID):
    # Generate an embedded link using the event ID
    embed_link = f"http://localhost:3000/form/{event_id}"
    return {"success": True, "embed_link": embed_link}


@app.get("/form/{form_id}")
async def get_form(
    form_id: UUID, 
    db: Session = Depends(get_db), 
    Authorize: AuthJWT = Depends()
):
    # Require authentication
    Authorize.jwt_required()

    # Query the form using the form_id
    form = db.query(EventForm).filter(EventForm.id == form_id).first()

    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    # Return the form data in JSON format
    return {
        "form_name": form.form_name,
        "form_data": form.form_data,
        "event_id": str(form.event_id)
    }

@app.get("/embed_form/{form_id}")
async def get_form(
    form_id: UUID, 
    db: Session = Depends(get_db)
):
    
    # Query the form using the form_id
    form = db.query(EventForm).filter(EventForm.id == form_id).first()

    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    # Return the form data in JSON format
    return {
        "form_name": form.form_name,
        "form_data": form.form_data,
        "event_id": str(form.event_id)
    }

@app.put("/update_form/{form_id}", response_class=JSONResponse)
async def update_form(
    form_id: UUID,
    payload: FormCreate,
    db: Session = Depends(get_db),
    # Authorize: AuthJWT = Depends(),
):
    # Authorize.jwt_required()
    # current_user_id = Authorize.get_jwt_subject()

    # Query the form to ensure it exists
    form = db.query(EventForm).filter(EventForm.id == form_id).first()
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    # Update the form's data
    form.form_name = payload.form_name
    form.form_data = payload.form_data

    db.commit()
    db.refresh(form)

    return {"success": True, "form_id": str(form.id), "message": "Form updated successfully"}
    
from fastapi import Body, HTTPException

@app.post("/create_form/{event_id}")
async def save_form(
    event_id: UUID,
    payload: FormCreate,
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends(),
):
    Authorize.jwt_required()
    current_user_id = Authorize.get_jwt_subject()

    # Log the incoming data for debugging
    print(payload)

    new_form = EventForm(
        event_id=event_id,
        form_name=payload.form_name,
        form_data=payload.form_data,
    )

    db.add(new_form)
    db.commit()
    db.refresh(new_form)

    return {"success": True, "form_id": str(new_form.id), "message": "Form created successfully"}

@app.post("/delete_form/{form_id}", response_class=JSONResponse)
async def delete_form(
    form_id: UUID,  # Accept form_id directly from the path
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    current_user_id = Authorize.get_jwt_subject()

    # Query the form to ensure it exists
    form = db.query(EventForm).filter(EventForm.id == form_id).first()
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    # Check authorization: Ensure the user is the owner of the event
    event = form.event
    if not event or event.user_id != current_user_id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this form")

    # Delete the form
    db.delete(form)
    db.commit()

    return {"success": True, "message": "Form deleted successfully"}


from io import BytesIO
import qrcode

def generate_qr_code(data: str) -> bytes:
    qr = qrcode.make(data)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    return buffer.getvalue()

@app.post("/submit_form/{form_id}", status_code=201)
async def submit_form(
    form_id: UUID,
    payload: dict,  # Include form data in the payload
    db: Session = Depends(get_db)
):
    # Get the form and associated event
    form = db.query(EventForm).filter(EventForm.id == form_id).first()
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    event = form.event
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Create the submission with default kit/lunch based on the event settings
    new_submission = EventFormSubmission(
        form_id=form_id,
        submission_data=payload["submission_data"],
        mode=payload.get("mode", "Online"),
        lunch=event.lunch,  # Default value from event
        kit=event.kit  # Default value from event
    )

    # Save submission in the database
    db.add(new_submission)
    db.commit()
    db.refresh(new_submission)

    # Generate a QR code with submission data and lunch/kit eligibility
    user_data = payload["submission_data"]
    user_data["lunch"] = new_submission.lunch
    user_data["kit"] = new_submission.kit

    # Generate QR code as binary data
    qr_code_data = generate_qr_code(user_data)

    # Save QR code binary data to the submission
    new_submission.qr_code = qr_code_data
    db.commit()

    return {"message": "Form submitted successfully", "submission_id": str(new_submission.id)}



from fastapi.responses import StreamingResponse

@app.get("/qr_code/{submission_id}", status_code=200)
async def get_qr_code(submission_id: UUID, db: Session = Depends(get_db)):
    submission = db.query(EventFormSubmission).filter(
        EventFormSubmission.id == submission_id
    ).first()

    if not submission or not submission.qr_code:
        raise HTTPException(status_code=404, detail="QR code not found")

    return StreamingResponse(BytesIO(submission.qr_code), media_type="image/png")



@app.get("/submissions/{form_id}", response_model=List[Dict[str, Any]])
async def get_form_submissions(form_id: UUID, db: Session = Depends(get_db)):
    # Query all submissions linked to the given form_id
    submissions = db.query(EventFormSubmission).filter(
        EventFormSubmission.form_id == form_id
    ).all()

    if not submissions:
        raise HTTPException(status_code=404, detail="No submissions found")

    # Return all submission data along with the mode
    result = [
        {
            "submission_data": submission.submission_data,
            "mode": submission.mode,
        }
        for submission in submissions
    ]

    return result


@app.get("/submission/{submission_id}", status_code=200)
async def get_submission_details(submission_id: UUID, db: Session = Depends(get_db)):
    # Query the submission by ID
    submission = db.query(EventFormSubmission).filter(EventFormSubmission.id == submission_id).first()

    # Check if the submission exists
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Return the submission details
    return {
        "submission_data": submission.submission_data,
        "mode": submission.mode,
        "qr_code": submission.qr_code.decode('latin1') if submission.qr_code else None 
    }


@app.post("/logout", response_class=JSONResponse)
async def logout(Authorize: AuthJWT = Depends()):
    try:
        # Simulate logout by revoking the user's JWT token in the client
        Authorize.unset_jwt_cookies()
        return JSONResponse(content={"success": True, "message": "Logout successful"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")  
    


@app.get("/event/{event_id}/registrations", response_model=list)
async def get_event_registrations(event_id: UUID, db: Session = Depends(get_db)):
    # Query to check if the event exists
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Retrieve all form submissions for the specified event
    submissions = (
        db.query(EventFormSubmission)
        .join(EventForm, EventForm.id == EventFormSubmission.form_id)
        .filter(EventForm.event_id == event_id)
        .all()
    )

    # Transform submission data into a list of dictionaries for easy JSON serialization
    result = [
        {
    
            "submission_data": submission.submission_data,
            "mode": submission.mode,
            "lunch": submission.lunch,
            "kit": submission.kit,
            "id": submission.id
        }
        for submission in submissions
    ]

    return result


from fastapi.responses import JSONResponse

@app.get("/validate_qr/{submission_id}")
async def validate_qr_code(submission_id: UUID, db: Session = Depends(get_db)):
    # Fetch the submission record
    submission = db.query(EventFormSubmission).filter(EventFormSubmission.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Fetch details from the submission
    return JSONResponse(content={
        "success": True,
        "submission_data": submission.submission_data,
        "lunch": submission.lunch,
        "kit": submission.kit,
        "mode": submission.mode
    })


@app.post("/create_id_card_fields/{event_id}/{form_id}")
async def create_id_card_fields(
    event_id: UUID,
    form_id: UUID,
    selected_fields: str = Form(...),  # Accept JSON string data as Form field
    custom_layout: str = Form(...),
    photo: UploadFile = File(...),  # Accept photo as a file upload
    db: Session = Depends(get_db)
):
    # Fetch event and form to verify their existence
    event = db.query(Event).filter(Event.id == event_id).first()
    form = db.query(EventForm).filter(EventForm.id == form_id).first()
    if not event or not form:
        raise HTTPException(status_code=404, detail="Event or Form not found")

    # Read the uploaded file and convert it to binary
    try:
        photo_data = await photo.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error reading photo") from e

    # Parse the JSON strings for `selected_fields` and `custom_layout`
    try:
        selected_fields_data = json.loads(selected_fields)
        custom_layout_data = json.loads(custom_layout)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON format")

    # Create new IDCardFields entry
    new_id_card_fields = IDCardFields(
        event_id=event_id,
        form_id=form_id,
        selected_fields=selected_fields_data,
        custom_layout=custom_layout_data,
        photo=photo_data  # Save the binary data of the photo
    )

    # Save the new IDCardFields entry
    db.add(new_id_card_fields)
    db.commit()
    db.refresh(new_id_card_fields)

    return {"message": "ID card fields created successfully", "id_card_fields_id": str(new_id_card_fields.id)}


@app.get("/id_card_fields/{event_id}", response_class=JSONResponse)
async def get_id_card_fields(
    event_id: UUID,
    db: Session = Depends(get_db)
):
    id_card_fields = db.query(IDCardFields).filter(
        IDCardFields.event_id == event_id
    ).first()
    
    if not id_card_fields:
        raise HTTPException(status_code=200)
    
    # Convert the photo to Base64 if it exists
    photo_base64 = base64.b64encode(id_card_fields.photo).decode('utf-8') if id_card_fields.photo else None
    
    return {
        "id": str(id_card_fields.id),
        "selected_fields": id_card_fields.selected_fields,
        "photo": photo_base64  # Send the photo as a Base64-encoded string
    }



@app.get("/form_by_event/{event_id}", response_class=JSONResponse)
async def get_form_by_event(
    event_id: UUID, 
    db: Session = Depends(get_db)
):
    # Query the first form using the event_id
    form = db.query(EventForm).filter(EventForm.event_id == event_id).first()

    if not form:
        raise HTTPException(status_code=200)

    # Return the form data in JSON format
    return {
        "form_name": form.form_name,
        "form_data": form.form_data,
        "event_id": str(form.event_id),
        "form_id": str(form.id)
    }


class SubmissionPayload(BaseModel):
    submission_data: dict  # Form data (name, email, phone, etc.)
    mode: str = "Online"  # Default mode to "Online"

@app.post("/reg-submitForms/{form_id}", status_code=201)
async def submit_form(
    form_id: UUID,
    payload: SubmissionPayload,
    db: Session = Depends(get_db)
):
    # Retrieve the form based on the form_id
    form = db.query(EventForm).filter(EventForm.id == form_id).first()
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    # Retrieve the event associated with the form
    event = form.event
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Create a new form submission entry with the payload data
    new_submission = EventFormSubmission(
        form_id=form_id,
        submission_data=payload.submission_data,
        mode=payload.mode,
        lunch=event.lunch,  # Default value from event
        kit=event.kit  # Default value from event
    )

    # Save the new submission to the database
    db.add(new_submission)
    db.commit()
    db.refresh(new_submission)

    # Prepare data for QR code generation, including lunch/kit eligibility
    user_data = payload.submission_data
    user_data["lunch"] = new_submission.lunch
    user_data["kit"] = new_submission.kit

    # Generate QR code as binary data
    qr_code_data = generate_qr_code(user_data)

    # Save QR code binary data to the submission record
    new_submission.qr_code = qr_code_data
    db.commit()

    return {"message": "Form submitted successfully", "submission_id": str(new_submission.id)}

@app.post("/delete_registration/{submission_id}", status_code=status.HTTP_200_OK)
async def delete_registration(
    submission_id: UUID,
    db: Session = Depends(get_db),
):
    # Query the registration entry to ensure it exists
    registration = db.query(EventFormSubmission).filter(EventFormSubmission.id == submission_id).first()

    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")

    # Delete the registration entry
    db.delete(registration)
    db.commit()

    return {"success": True, "message": "Registration deleted successfully"}

class UpdateRegistrationRequest(BaseModel):
    submission_data: dict
    mode: Optional[str] = "Online"
@app.put("/update-registration/{submission_id}", response_model=dict)
async def update_registration(
    submission_id: UUID,
    payload: UpdateRegistrationRequest,
    db: Session = Depends(get_db),
    # Authorize: AuthJWT = Depends()
):
    """
    Update a specific event form submission by submission_id.
    """
    # Validate the JWT token
    # try:
    #     Authorize.jwt_required()
    # except Exception as e:
    #     raise HTTPException(status_code=401, detail="Token expired or invalid.")

    # Fetch the submission entry from the database
    submission = db.query(EventFormSubmission).filter(EventFormSubmission.id == submission_id).first()

    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found.")

    # Update submission data
    if payload.submission_data:
        submission.submission_data = payload.submission_data

    if payload.mode:
        submission.mode = payload.mode

    # Regenerate QR Code if submission_data is updated
    if payload.submission_data:
        updated_data = payload.submission_data
        updated_data["lunch"] = submission.lunch
        updated_data["kit"] = submission.kit
        qr_code_data = generate_qr_code(updated_data)
        submission.qr_code = qr_code_data

    # Save the updates
    try:
        db.commit()
        db.refresh(submission)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating submission: {str(e)}")

    return {
        "success": True,
        "message": "Submission updated successfully.",
        "submission_id": str(submission.id),
        "submission_data": submission.submission_data,
        "mode": submission.mode,
        "qr_code": submission.qr_code.decode('latin1') if submission.qr_code else None,
    }


@app.get("/admin_events", response_class=JSONResponse)
async def get_all_events(
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    current_user_id = Authorize.get_jwt_subject()

    # Check if the user is a super admin
    user = db.query(User).filter(User.id == current_user_id).first()
    if not user or not user.is_superadmin:
        raise HTTPException(status_code=403, detail="Unauthorized access")

    # Fetch all events
    events = db.query(Event).all()
    return {
        "success": True,
        "events": [
            {
                "event_id": str(event.id),
                "event_name": event.event_name,
                "venue_address": event.venue_address,
                "event_date": event.event_date.isoformat(),
                "status": event.status.name
            }
            for event in events
        ]
    }


@app.get("/admin_registrations", response_class=JSONResponse)
async def get_all_registrations(
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    current_user_id = Authorize.get_jwt_subject()

    # Check if the user is a super admin
    user = db.query(User).filter(User.id == current_user_id).first()
    if not user or not user.is_superadmin:
        raise HTTPException(status_code=403, detail="Unauthorized access")

    # Fetch all registrations
    registrations = db.query(EventFormSubmission).all()
    return {
        "success": True,
        "registrations": [
            {
                "submission_id": str(reg.id),
                "form_id": str(reg.form_id),
                "submission_data": reg.submission_data,
                "mode": reg.mode,
                "lunch": reg.lunch,
                "kit": reg.kit
            }
            for reg in registrations
        ],
        "count": len(registrations)
    }


@app.post("/user/{user_id}/subuser", response_class=JSONResponse)
async def create_subuser(
    user_id: str,  # Accept the main user's ID as a URL parameter
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    create_event: bool = Form(False),
    create_form: bool = Form(False),
    view_registrations: bool = Form(False),
    db: Session = Depends(get_db)
):
    # Step 1: Validate the main user using the user_id
    main_user = db.query(User).filter(User.id == user_id).first()
    if not main_user:
        raise HTTPException(status_code=404, detail="Main user not found")
    if not main_user.is_active:
        raise HTTPException(status_code=403, detail="Main user account is inactive")



    # Step 3: Create the sub-user with a reference to the main user
    subuser = SubUser(
        main_user_id=main_user.id,  # Use the URL parameter user_id as foreign key
        name=name,
        email=email,
        password=password,
        create_event=create_event,
        create_form=create_form,
        view_registrations=view_registrations,
    )
    db.add(subuser)
    db.commit()
    db.refresh(subuser)

    # Step 4: Return success response
    return JSONResponse(content={"success": True, "subuser_id": str(subuser.id)})

@app.put("/subuser/{sub_user_id}/{user_id}", response_class=JSONResponse)
async def edit_subuser(
    sub_user_id: UUID,
    user_id: str,# Sub-user ID as a URL parameter
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    create_event: bool = Form(...),
    create_form: bool = Form(...),
    view_registrations: bool = Form(...),
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    try:
    
        current_user_id = user_id

        # Retrieve the sub-user from the database
        subuser = db.query(SubUser).filter(SubUser.id == sub_user_id, SubUser.main_user_id == current_user_id).first()
        if not subuser:
            raise HTTPException(status_code=404, detail="Sub-user not found or unauthorized")

        # Update the sub-user's details
        subuser.name = name
        subuser.email = email
        subuser.password = password  # Optionally hash the password here
        subuser.create_event = create_event
        subuser.create_form = create_form
        subuser.view_registrations = view_registrations

        # Commit the changes to the database
        db.commit()
        db.refresh(subuser)

        return JSONResponse(content={"success": True, "message": "Sub-user updated successfully"}, status_code=200)

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating sub-user: {str(e)}")

@app.get("/user/{user_id}/subusers", response_class=JSONResponse)
async def get_subusers(user_id: str, db: Session = Depends(get_db)):
    # Step 1: Validate the main user using the user_id
    main_user = db.query(User).filter(User.id == user_id).first()
    if not main_user:
        raise HTTPException(status_code=404, detail="Main user not found")
    
    # Step 2: Fetch all sub-users associated with the main user
    subusers = db.query(SubUser).filter(SubUser.main_user_id == user_id).all()

    # Step 3: Format the response
    subusers_list = [
        {
            "sub_user_id": str(subuser.id),
            "name": subuser.name,
            "email": subuser.email,
            "password": subuser.password,
            "create_event": subuser.create_event,
            "create_form": subuser.create_form,
            "view_registrations": subuser.view_registrations,
        }
        for subuser in subusers
    ]

    # Step 4: Return the response
    return JSONResponse(content={"success": True, "subusers": subusers_list})

@app.get("/subuser/{sub_user_id}/{user_id}", response_class=JSONResponse)
async def get_subuser_details(
    sub_user_id: UUID,
    user_id: str,# Sub-user ID as a URL parameter
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    try:
       
        current_user_id = user_id

        # Retrieve the sub-user from the database
        subuser = db.query(SubUser).filter(SubUser.id == sub_user_id, SubUser.main_user_id == current_user_id).first()
        if not subuser:
            raise HTTPException(status_code=404, detail="Sub-user not found or unauthorized")

        # Prepare the response with sub-user details
        subuser_data = {
            "sub_user_id": str(subuser.id),
            "name": subuser.name,
            "email": subuser.email,
            "password": subuser.password,
            "create_event": subuser.create_event,
            "create_form": subuser.create_form,
            "view_registrations": subuser.view_registrations,
        }

        return JSONResponse(content={"success": True, "subuser": subuser_data}, status_code=200)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving sub-user: {str(e)}")


@app.get("/admin_dashboard/{super_user_id}", response_class=JSONResponse)
async def get_all_events_count(
    super_user_id: UUID,
    db: Session = Depends(get_db),
    # Authorize: AuthJWT = Depends()
):
    # Authorize.jwt_required()
    # current_user_id = Authorize.get_jwt_subject()

    # Check if the user is a super admin
    user = db.query(User).filter(User.id == super_user_id).first()
    if not user or not user.is_superadmin:
        raise HTTPException(status_code=403, detail="Unauthorized access")

    # Get the count of all events
    event_count = db.query(Event).count()
    registration_count = db.query(EventFormSubmission).count()
    users_count = db.query(User).count()

    return {
        "success": True,
        "event_count": event_count,
        "registration_count" :registration_count,
        "users_count": users_count
    }

@app.get("/admin_edit_event/{event_id}", response_class=JSONResponse)
async def get_event(event_id: str, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    try:

        event = db.query(Event).filter(Event.id == event_id).first()

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
    
@app.put("/admin_update_event/{event_id}", response_class=JSONResponse)
async def edit_event(
    event_id: UUID,
    event_name: str = Form(...),
    venue_address: str = Form(...),
    event_date: str = Form(...),
    audience: bool = Form(...),
    delegates: bool = Form(...),
    speaker: bool = Form(...),
    nri: bool = Form(...),
    lunch: bool = Form(...),
    kit: bool = Form(...),
    db: Session = Depends(get_db),
    
):
    try:

        # Retrieve the event from the database
        event = db.query(Event).filter(Event.id == event_id).first()
        if not event:
            raise HTTPException(status_code=404, detail="Event not found or unauthorized")

        # Update the event with new data
        event.event_name = event_name
        event.venue_address = venue_address
        event.event_date = event_date  # Convert to date if necessary
        event.audience = audience
        event.delegates = delegates
        event.speaker = speaker
        event.nri = nri
        event.lunch = lunch
        event.kit = kit

        # Commit the changes to the database
        db.commit()
        db.refresh(event)

        return JSONResponse(content={"success": True, "message": "Event updated successfully"}, status_code=200)

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating event: {str(e)}")


@app.post("/admin_delete_event", status_code=status.HTTP_200_OK)
async def delete_event(
    event_id: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        

        # Check if the event exists and is owned by the current user
        event = db.query(Event).filter(Event.id == event_id).first()
        if not event:
            raise HTTPException(status_code=404, detail="Event not found or unauthorized")

        # Ensure related submissions are deleted to avoid foreign key constraint issues
        for form in event.forms:
            db.query(EventFormSubmission).filter(EventFormSubmission.form_id == form.id).delete()
            db.delete(form)

        # Delete the event
        db.delete(event)
        db.commit()

        return JSONResponse(content={"success": True, "message": "Event deleted successfully"}, status_code=200)

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting event: {str(e)}")

@app.post("/admin_delete_registration/{submission_id}", status_code=status.HTTP_200_OK)
async def delete_registration(
    submission_id: UUID,
    db: Session = Depends(get_db),
):
    # Query the registration entry to ensure it exists
    registration = db.query(EventFormSubmission).filter(EventFormSubmission.id == submission_id).first()

    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")

    # Delete the registration entry
    db.delete(registration)
    db.commit()

    return {"success": True, "message": "Registration deleted successfully"}

class UpdateRegistrationRequest(BaseModel):
    submission_data: dict
    mode: Optional[str] = "Online"
@app.put("/admin_update-registration/{submission_id}", response_model=dict)
async def update_registration(
    submission_id: UUID,
    payload: UpdateRegistrationRequest,
    db: Session = Depends(get_db),
    # Authorize: AuthJWT = Depends()
):
    """
    Update a specific event form submission by submission_id.
    """

    # Fetch the submission entry from the database
    submission = db.query(EventFormSubmission).filter(EventFormSubmission.id == submission_id).first()

    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found.")

    # Update submission data
    if payload.submission_data:
        submission.submission_data = payload.submission_data

    if payload.mode:
        submission.mode = payload.mode

    # Regenerate QR Code if submission_data is updated
    if payload.submission_data:
        updated_data = payload.submission_data
        updated_data["lunch"] = submission.lunch
        updated_data["kit"] = submission.kit
        qr_code_data = generate_qr_code(updated_data)
        submission.qr_code = qr_code_data

    # Save the updates
    try:
        db.commit()
        db.refresh(submission)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating submission: {str(e)}")

    return {
        "success": True,
        "message": "Submission updated successfully.",
        "submission_id": str(submission.id),
        "submission_data": submission.submission_data,
        "mode": submission.mode,
        "qr_code": submission.qr_code.decode('latin1') if submission.qr_code else None,
    }


@app.get("/admin_form_by_event/{event_id}", response_class=JSONResponse)
async def get_form_by_event(
    event_id: UUID, 
    db: Session = Depends(get_db)
):
    # Query the first form using the event_id
    form = db.query(EventForm).filter(EventForm.event_id == event_id).first()

    if not form:
        raise HTTPException(status_code=200)

    # Return the form data in JSON format
    return {
        "form_name": form.form_name,
        "form_data": form.form_data,
        "event_id": str(form.event_id),
        "form_id": str(form.id)
    }

@app.post("/resetpassword", response_class=JSONResponse)
async def reset_password(
    email: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if passwords match
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # Validate the user in the `users` table
    user = db.query(User).filter(User.email == email).first()
    if user:
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is inactive")
        
        # Update the password
        user.password = new_password  # Consider hashing the password here
        db.commit()

        

        return JSONResponse(content={
            "success": True,
            "message": "Password reset successfully",
            "user_type": "User",
            "user_email": user.email,
            "user_password":user.password
        })

    # Validate the user in the `sub_users` table
    subuser = db.query(SubUser).filter(SubUser.email == email).first()
    if subuser:
        # Update the password
        subuser.password = new_password  # Consider hashing the password here
        db.commit()

        return JSONResponse(content={
            "success": True,
            "message": "Password reset successfully",
            "user_type": "SubUser",
            "user_email": subuser.email
        })

    # If no user is found
    raise HTTPException(status_code=404, detail="Email not found")


# @app.get("/get_names/{form_id}", response_class=JSONResponse)
# async def get_names_by_form_id(
#     form_id: UUID,
#     db: Session = Depends(get_db),
# ):
#     try:
#         # Query to find the submission with the given form_id
#         form_submission = db.query(EventFormSubmission).filter(EventFormSubmission.form_id == form_id).first()

#         if form_submission:
#             # Extract "Name" values from the JSONB column (submission_data)
#             submission_data = form_submission.submission_data  # Assuming submission_data is already parsed as a dictionary
#             if submission_data and "Name" in submission_data:
#                 name = submission_data["Name"]
#                 response_data = {
#                     "success": True,
#                     "message": "Names retrieved successfully",
#                     "Form_id": str(form_submission.form_id),
#                     "Name": name,
#                 }
#                 return JSONResponse(content=response_data, status_code=200)
#             else:
#                 return JSONResponse(
#                     content={"success": False, "message": "No Name field found in submission data"},
#                     status_code=404,
#                 )
#         else:
#             return JSONResponse(
#                 content={"success": False, "message": "Form submission not found"},
#                 status_code=404,
#             )
#     except Exception as e:
#         return JSONResponse(
#             content={"success": False, "message": f"An error occurred: {str(e)}"},
#             status_code=500,
#         )



@app.get("/get_submission_data/{form_id}", response_class=JSONResponse)
async def get_submission_data_by_form_id(
    form_id: UUID,
    db: Session = Depends(get_db),
):
    try:
        # Query to get all submissions for the given form_id
        submissions = db.query(EventFormSubmission).filter(EventFormSubmission.form_id == form_id).all()

        if submissions:
            # Prepare the response data
            response_data = []
            for submission in submissions:
                submission_data = submission.submission_data
                if submission_data:
                    # Check if lunch and kit are set, default to False if not
                    lunch_status = submission.lunch if submission.lunch is not None else False
                    kit_status = submission.kit if submission.kit is not None else False
                    
                    # Append data for each submission
                    response_data.append({
                        "submission_data": submission_data,  # Nested submission data
                        "lunch_status": lunch_status,  # Lunch status
                        "kit_status": kit_status,  # Kit status
                    })
                else:
                    # If submission data is empty, return an error
                    return JSONResponse(
                        content={"success": False, "message": f"Form with ID {form_id} has empty submission data."},
                        status_code=404,
                    )

            return JSONResponse(
                content={"success": True, "message": "Submissions retrieved successfully", "data": response_data},
                status_code=200
            )
        else:
            return JSONResponse(
                content={"success": False, "message": f"No submissions found for form_id {form_id}."},
                status_code=404,
            )

    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": f"An error occurred: {str(e)}"},
            status_code=500,
        )
