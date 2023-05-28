from db import db
import users_dao
from flask import Flask
from flask import request

from db import User
from db import Item
from db import Conversation
from db import Message
from db import Asset

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


# TODO: remove/change later !!!
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

# TODO: research best of updating account info i.e. how to handle sensitive data
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


# TODO: maybe delete this later since items are already contained in user object
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

  # TODO: create stricter validity checkers for all of the input fields
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
  # TODO: create stricter validity checkers for all of the input fields
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


# ---------- MESSAGE/CONVERSATION ----------------------------------------------
# TODO: maybe provide the item's information (either by default in the message 
# itself or provide item data in success response)
@app.route("/items/<int:item_id>/contact/", methods=["POST"])
def contact_owner(item_id):
  """
  Endpoint for contacting the owner of an item by sending a message
  """
  # first get the item and check that it exists
  item = Item.query.filter_by(id=item_id).first()

  if item is None:
    return failure_response("item not found")

  # get the item's owner
  owner_id = item.owner_id
  owner = User.query.filter_by(id=owner_id).first()
  if owner is None:
    return failure_response("owner not found")

  # retrieve json data
  body = json.loads(request.data)
  send_id = body.get("sender_id")
  message = body.get("message_text")

  # get message sender
  sender = User.query.filter_by(id=send_id).first()
  
  # check that all necessary data was provided in the request and is valid
  if send_id is None or sender is None:
    return failure_response("sender id not found or invalid")

  if message is None:
    return failure_response("please provide a message", 403)

  # check if conversation exists, and if it doesn't, create a new one
  if (owner.has_conversation(sender)[0]):
    conversation_id = owner.has_conversation(sender)[1]
    conversation = Conversation.query.filter_by(id=conversation_id).first()
  else:
    # if this is a new conversation, the owner cannot be the sender
    if send_id == owner_id:
      return failure_response("owner cannot be sender", 403)
    conversation = Conversation()
    conversation.owner.append(User.query.filter_by(id=owner_id).first())
    conversation.inquirer.append(User.query.filter_by(id=send_id).first())
    conversation_id = conversation.id
    db.session.add(conversation)

  # create message
  new_message = Message(
    message_text = message, 
    sender_id = send_id, 
    conversation_id = conversation_id,
    timestamp = datetime.datetime.now()
  )

  # commit changes to database and return success response
  db.session.add(new_message)
  db.session.commit()
  return success_response({"conversation": conversation.serialize()})


@app.route("/users/<int:user_id>/conversations/")
def get_user_conversations(user_id):
  """
  Endpoint for getting a specific user's conversations 
  """
  user = User.query.filter_by(id=user_id).first()
  if user is None:
    return failure_response("user not found")

  conversations = []
  for convo in (user.conversations_where_owner + user.conversations_where_inquirer):
    conversations.append(convo.serialize())
  return success_response({"conversations": conversations})


@app.route("/users/<int:user_1_id>/conversations/<int:user_2_id>/")
def get_conversation(user_1_id, user_2_id):
  """
  Endpoint for getting a specific conversation from a user's conversations
  """
  # find user first to save time (conversations >= users)
  user_1 = User.query.filter_by(id=user_1_id).first()
  user_2 = User.query.filter_by(id=user_2_id).first()
  if user_1 is None or user_2 is None:
    return failure_response("user(s) not found")

  if user_1.has_conversation(user_2)[0]:
    conversation_id = user_1.has_conversation(user_2)[1]
    conversation = Conversation.query.filter_by(id=conversation_id).first()
    return success_response({"conversation": conversation.serialize()})
  else:
    return failure_response("Conversation not found")


@app.route("/users/<int:user_id>/conversations/<int:conversation_id>/", methods=["POST"])
def send_message(user_id, conversation_id):
  """
  Endpoint for sending message in a conversation where user_id is the user id of
  the message sender
  """
  # ensure that user and conversation are valid
  user = User.query.filter_by(id=user_id).first()
  if user is None:
    return failure_response("user not found")

  conversation = None
  for convo in (user.conversations_where_owner + user.conversations_where_inquirer):
    if convo.id == conversation_id:
      conversation = convo
      break

  if conversation is None:
    return failure_response("Conversation not found")

  # retrieve json data
  body = json.loads(request.data)
  message = body.get("message_text")
  if message is None:
    return failure_response("please provide a message", 403)

  # TODO: make a new message with user_id as sender_id and add to database, 
  # provide the conversation as success response
  new_message = Message(
    conversation_id = conversation.id,
    message_text = message,
    sender_id = user_id,
    timestamp = datetime.datetime.now()
  )

  db.session.add(new_message)
  db.session.commit()
  return success_response({"conversation": conversation.serialize()})


# ---------- IMAGES ------------------------------------------------------------

# TODO: change the way this is being done later as we'll want it to happen when
# a post is being made
@app.route("/upload/", methods=["POST"])
def upload():
  """
  Endpoint for uploading an image to AWS given its base64 form, 
  then storing/returning the URL of that image
  """
  body = json.loads(request.data)
  # maybe just have image_data be part of the request informationfor posting an
  # item 
  image_data = body.get("image_data")

  if image_data is None:
    return failure_response("No base64 image found")

  asset = Asset(image_data=image_data)
  db.session.add(asset)
  db.session.commit()

  return success_response(asset.serialize(), 201)

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=8000, debug=True)  
