import datetime
import hashlib
import os

import bcrypt
import base64
import boto3
import io 
from io import BytesIO
from mimetypes import guess_extension, guess_type
from PIL import Image
import random
import re
import string

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Image handling
EXTENSIONS = ["png", "jpeg", "jpg"]
BASE_DIR = os.getcwd()
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")
S3_BASE_URL = f"https://{S3_BUCKET_NAME}.s3.us-east-1.amazonaws.com"

# ASSET
class Asset(db.Model):
  """
  Asset model  
  """
  __tablename__ = "asset"
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)
  base_url = db.Column(db.String, nullable=True)
  salt = db.Column(db.String, nullable=True)
  extension = db.Column(db.String, nullable=True)
  width = db.Column(db.Integer, nullable=True)
  height = db.Column(db.Integer, nullable=True)

  def __init__(self, **kwargs):
    """
    Initializes an Asset object
    """
    self.create(kwargs.get("image_data"))

  
  def create(self, image_data):
    """
    Given an image in base64 encoding, does the following:
    1. Rejects the image if it is not a supported file type
    2. Generate a random string for the image filename
    3. Decodes the image and attempts to upload it to AWS
    """
    try:
      ext = guess_extension(guess_type(image_data)[0])[1:]
      if ext not in EXTENSIONS:
        raise Exception(f"Extension {ext} is not valid")
      
      salt = "".join(
        random.SystemRandom().choice(
          string.ascii_uppercase + string.digits
        )
        for _ in range(16)
      )

      img_str = re.sub("^data:image/.+;base64,", "", image_data)
      img_data = base64.b64decode(img_str)
      img = Image.open(BytesIO(img_data))

      self.base_url = S3_BASE_URL
      self.salt = salt
      self.extension = ext
      self.width = img.width
      self.height = img.height


      img_filename = f"{self.salt}.{self.extension}" 
      self.upload(img, img_filename)

    except Exception as e:
      print({"Error when creating image:" {e}})

  def upload(self, img, img_filename):
    """
    Attempts to upload the image into the specified S3 Bucket
    """
    try:
      # save image into temporary location
      img_temp_loc = f"{BASE_DIR}/{img_filename}"
      img.save(img_temp_loc)

      # upload img into S3 Bucket
      s3_client = boto3.client("s3")
      s3_client.upload_file(img_temp_loc, S3_BUCKET_NAME, img_filename)

      s3_resource = boto3.resource("s3")
      object_acl = s3_resource.ObjectAcl(S3_BUCKET_NAME, img_filename)
      object_acl.put(ACL = "public-read") 

      # removed image from temp location
      os.remove(img_temp_loc)
    except Exception as e:
      print({"Error when uploading image:" {e}})

  def serialize(self):
    """
    Serializes an Asset object
    """
    return {
      "url": f"{self.base_url}/{self.salt}.{self.extension}"
    }

# Association tables
conversation_association_table_owner = db.Table(
  "conversation_association_owner",
  db.Column("owner_id", db.Integer, db.ForeignKey("user.id")),
  db.Column("conversation_id", db.Integer, db.ForeignKey("conversation.id"))
)

conversation_association_table_inquirer = db.Table(
  "conversation_association_inquirer",
  db.Column("inquirer_id", db.Integer, db.ForeignKey("user.id")),
  db.Column("conversation_id", db.Integer, db.ForeignKey("conversation.id"))
)

# TODO: add name/username, and necessary address fields to User

# USER
class User(db.Model):
  """
  User model
  """
  __tablename__ = "user"
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)

  # User information
  email = db.Column(db.String, nullable=False, unique=True)
  password_digest = db.Column(db.String, nullable=False)

  # Relationships
  items = db.relationship("Item", cascade="delete")
  conversations_where_owner = db.relationship("Conversation", 
  secondary=conversation_association_table_owner, back_populates="owner")
  conversations_where_inquirer = db.relationship("Conversation", 
  secondary=conversation_association_table_inquirer, back_populates="inquirer")


  # Session information
  session_token = db.Column(db.String, nullable=False, unique=True)
  session_expiration = db.Column(db.DateTime, nullable=False)
  update_token = db.Column(db.String, nullable=False, unique=True)


  def __init__(self, **kwargs):
    """
    Initializes a User object
    """
    self.email = kwargs.get("email")
    self.password_digest = bcrypt.hashpw(kwargs.get("password").encode("utf8"), bcrypt.gensalt(rounds=13))
    self.renew_session()

  def serialize(self):
    """
    Serializes a User object
    """
    return {
      "id": self.id,
      "email": self.email,
      "items": [item.serialize() for item in self.items],
      "conversations": [convo.serialize() for convo in self.conversations_where_owner] + 
      [convo.serialize() for convo in self.conversations_where_inquirer]
    }

  def simple_serialize(self):
    """
    Serializes a User object with only their id
    """
    return {"id": self.id}
    

  # TODO: verify that this is ok to do (might be not very efficient)
  def has_conversation(self, other_user):
    """
    Returns true with the corresponding conversation id if this user has an 
    existing conversation with this other user and false with -1 otherwise
    """
    for conversation in self.conversations_where_inquirer:
      if conversation.owner[0].id == other_user.id:
        return True, conversation.id
    for conversation in self.conversations_where_owner:
      if conversation.inquirer[0].id == other_user.id:
        return True, conversation.id

    return False, -1

  # ---------- AUTHENTICATION --------------------------------------------------
  def _urlsafe_base_64(self):
    """
    Randomly generates hashed tokens (used for session/update tokens)
    """
    return hashlib.sha1(os.urandom(64)).hexdigest()


  def renew_session(self):
    """
    Renews the session, i.e.
    1. Creates a new session token
    2. Sets the expiration time of the session to be a day from now
    3. Creates a new update token
    """
    self.session_token = self._urlsafe_base_64()
    self.session_expiration = datetime.datetime.now() + datetime.timedelta(days=1)
    self.update_token = self._urlsafe_base_64()


  def verify_password(self, password):
    """
    Verifies the password of a user
    """
    return bcrypt.checkpw(password.encode("utf8"), self.password_digest)
  

  def verify_session_token(self, session_token):
    """
    Verifies the session token of a user
    """
    return session_token == self.session_token and datetime.datetime.now() < self.session_expiration


  def verify_update_token(self, update_token):
    """
    Verifies the update token of a user
    """
    return update_token == self.update_token


# ITEM
class Item(db.Model):
  """
  Item model
  """
  __tablename__ = "item"
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)

  # Item information
  title = db.Column(db.String, nullable=False)
  description = db.Column(db.String, nullable=False)
  size = db.Column(db.String, nullable=False)
  age = db.Column(db.String, nullable=False)
  gender = db.Column(db.String, nullable=False)
  condition = db.Column(db.String, nullable=False)
  date_posted = db.Column(db.Integer, nullable = False)
  donated = db.Column(db.Boolean, nullable = False)
  owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

  def __init__(self, **kwargs):
    """
    Initializes an Item object
    """
    self.title = kwargs.get("title")
    self.description = kwargs.get("description", "")
    self.size = kwargs.get("size")
    self.age = kwargs.get("age")
    self.gender = kwargs.get("gender")
    self.condition = kwargs.get("condition")
    self.date_posted = datetime.datetime.now()
    self.owner_id = kwargs.get("owner_id")
    self.donated = kwargs.get("donated")

  def serialize(self):
    """
    Serialize an Item object
    """
    return {
      "id": self.id, 
      "owner_id": self.owner_id,
      "title": self.title,
      "description": self.description, 
      "size": self.size, 
      "age": self.age, 
      "gender": self.gender, 
      "condition": self.condition,
      "date_posted": self.date_posted,
      "donated": self.donated
    }


# CONVERSATION
class Conversation(db.Model):
  """
  Conversation model
  """
  __tablename__ = "conversation"
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)

  owner = db.relationship("User", secondary=conversation_association_table_owner, 
  back_populates="conversations_where_owner")
  inquirer = db.relationship("User", secondary=conversation_association_table_inquirer, 
  back_populates="conversations_where_inquirer")
  messages = db.relationship("Message", cascade="delete")

  # TODO: see if we can delete this
  def __init__(self, **kwargs):
    """
    Initializes a Conversation object
    """

  def serialize(self):
    """
    Serializes a Conversation object
    """
    return {
      "id": self.id,
      "owner": [o.simple_serialize() for o in self.owner][0], 
      "inquirer": [i.simple_serialize() for i in self.inquirer][0],
      "messages": [message.seralize() for message in self.messages]
    }

# MESSAGE
class Message(db.Model):
  """
  Message model
  """
  __tablename__ = "message"
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)

  # Message information
  message_text = db.Column(db.String, nullable=False)
  timestamp = db.Column(db.Integer, nullable = False)
  conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"), nullable=False)
  sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

  def __init__(self, **kwargs):
    """
    Initializes a Message object
    """
    self.message_text = kwargs.get("message_text")
    self.conversation_id = kwargs.get("conversation_id")
    self.sender_id = kwargs.get("sender_id")
    self.timestamp = datetime.datetime.now()

  def seralize(self):
    """
    Serializes a Message object
    """
    return {
      "id": self.id, 
      "sender_id": self.sender_id,
      "message_text": self.message_text,
      "timestamp": self.timestamp
    }

