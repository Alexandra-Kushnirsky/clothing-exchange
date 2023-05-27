import datetime
import hashlib
import os

import bcrypt
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

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
    Serializes a user object
    """
    return {
      "id": self.id,
      "email": self.email
    }

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
    # relationships go here

  def serialize(self):
    """
    Serialize an item object
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

