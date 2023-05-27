from db import db
import users_dao
from flask import Flask
from flask import request

from db import User
from db import Item

import datetime
import json
import os

app = Flask(__name__)
db_filename = "threadshare.db"

# setup config
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db_filename
app.config["SQLALCHEMY_ECHO"] = True

# initialize app
db.init_app(app)
with app.app_context():
    db.create_all()

# generalized response formats
def success_response(data, code=200):
  return json.dumps(data), code


def failure_response(message, code=404):
  return json.dumps({"error": message}), code


# remove later !!!
@app.route("/")
def hello():
  return json.dumps({"message":"Hello, World!"})

# ---------- AUTHENTICATION ----------------------------------------------------
def extract_token(request):
  """
  Helper method for extracting the token
  """
  auth_header = request.headers.get("Authorization")
  if auth_header is None:
    return failure_response("missing auth header")

  bearer_token = auth_header.replace("Bearer", "").strip()
  if not bearer_token:
    return failure_response("invalid auth header")
  
  return True, bearer_token


@app.route("/register/", methods=["POST"])
def register_account():
  """
  Endpoint for registering a user
  """
  body = json.loads(request.data)
  email = body.get("email")
  password = body.get("password")

  if email is None or password is None:
    return failure_response("Invalid email or password")

  created, user = users_dao.create_user(email, password)

  if not created:
    return failure_response("User already exists")

  return success_response(
    {
      "session_token": user.session_token,
      "session_expiration": str(user.session_expiration),
      "update_token": user.update_token
    }
  )


@app.route("/login/", methods=["POST"])
def login():
  """
  Endpoint for logging in a user
  """
  body = json.loads(request.data)
  email = body.get("email")
  password = body.get("password")

  if email is None or password is None:
    return failure_response("Invalid email or password", 400)

  success, user = users_dao.verify_credentials(email, password)

  if not success:
    return failure_response("Invalid email or password", 400)

  return success_response(
    {
      "session_token": user.session_token,
      "session_expiration": str(user.session_expiration),
      "update_token": user.update_token
    }
  )


@app.route("/session/", methods=["POST"])
def update_session():
  """
  Endpoint for updating a user's session
  """
  success, update_token = extract_token(request)

  if not success:
    return update_token

  user = users_dao.renew_session(update_token)

  if user is None:
    return failure_response("invalid update token")
  
  return success_response(
    {
      "session_token": user.session_token,
      "session_expiration": str(user.session_expiration),
      "update_token": user.update_token
    }
  )


@app.route("/secret/", methods=["GET"])
def secret_message():
  """
  Endpoint for verifying a session token and returning a secret message
  """
  success, session_token = extract_token(request)
  
  if not success:
    return session_token

  user = users_dao.get_user_by_session_token(session_token)
  if user is None or not user.verify_session_token(session_token):
    return failure_response("invalid session token")

  return success_response("yay :-)")


@app.route("/logout/", methods=["POST"])
def logout():
  """
  Endpoint for logging out a user
  """
  success, session_token = extract_token(request)

  if not success:
    return session_token

  user = users_dao.get_user_by_session_token
  if not user or not user.verify_session_token(session_token):
    return failure_response("invalid session token", 400)

  user.session_expiration = datetime.datetime.now()
  db.session.commit()

  return success_response("user has successfully logged out")


# ---------- USER --------------------------------------------------------------
@app.route("/")
@app.route("/users/")
def get_all_users():
  """
  Endpoint for getting all users
  """
  users = []
  for user in User.query.all():
    users.append(user.serialize())
  return success_response({"users": users})


@app.route("/users/<int:user_id>/")
def get_user(user_id):
  """
  Endpoint for getting a user by id
  """
  user = User.query.filter_by(id=user_id).first()

  if user is None:
    failure_response("user not found")

  return success_response(user.serialize())

# LATER: research best of updating account info i.e. how to handle sensitive data
# and implement edit account, as well as delete account

# ---------- ITEM --------------------------------------------------------------
@app.route("/items/")
def get_all_items():
  """
  Endpoint for getting all items
  """
  items = []
  for item in Item.query.all():
    items.append(item.serialize())
  return success_response({"items": items})


@app.route("/users/<int:user_id>/items/")
def get_user_items(user_id):
  """
  Endpoint for getting items of a specific user
  """
  items = []
  for item in (Item.query.filter_by(owner_id=user_id)):
    items.append(item.serialize())
  return success_response({"items": items})


@app.route("/users/<int:user_id>/items/", methods=["POST"])
def post_item(user_id):
  """
  Endpoint for adding an item to a user's listings
  """
  user = User.query.filter_by(id=user_id).first()

  if user is None:
    failure_response("user not found")

  body = json.loads(request.data)
  new_item = Item(
    title = body.get("title"),
    description = body.get("description"),
    size = body.get("size"),
    age = body.get("age"),
    gender = body.get("gender"),
    condition = body.get("condition"),
    date_posted = datetime.datetime.now(),
    owner_id = user_id,
    donated = False
  )

  db.session.add(new_item)
  db.session.commit()
  return success_response(new_item.serialize())


@app.route("/users/<int:user_id>/items/<int:item_id>/", methods=["POST"])
def update_item(user_id, item_id):
  """
  Endpoint for updating an item from user's listings
  """
  user = User.query.filter_by(id=user_id).first()
  if user is None:
    return failure_response("user not found")

  item = Item.query.filter_by(id=item_id).first()
  if item is None or Item.query.filter_by(id=item_id, owner_id=user_id) is None:
    return failure_response("item not found")

  body = json.loads(request.data)

  item.title = body.get("title", item.title)
  item.description = body.get("description", item.description)
  item.size = body.get("size", item.size)
  item.age = body.get("age", item.age)
  item.gender = body.get("gender", item.gender)
  item.condition = body.get("condition", item.condition)
  item.donated = body.get("donated", item.donated)
  
  db.session.commit()
  return success_response(item.serialize())
  

@app.route("/users/<int:user_id>/items/<int:item_id>/", methods=["DELETE"])
def delete_item(user_id, item_id):  
  """
  Endpoint for deleting an item from user's listings
  """
  user = User.query.filter_by(id=user_id).first()
  if user is None:
    return failure_response("user not found")

  item = Item.query.filter_by(id=item_id).first()
  if item is None or Item.query.filter_by(id=item_id, owner_id=user_id) is None:
    return failure_response("item not found")

  db.session.delete(item)
  db.session.commit()
  return success_response(item.serialize())

@app.route("/items/<int:item_id>/")
def get_item(item_id):
  """
  Endpoint for getting a specific item by its id
  """
  item = Item.query.filter_by(id=item_id).first()

  if item is None:
    failure_response("item not found")

  return success_response(item.serialize())



if __name__ == "__main__":
  app.run(host="0.0.0.0", port=8000, debug=True)  

