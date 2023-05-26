from db import db
import users_dao
from flask import Flask
from flask import request

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
  pass

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
  pass

@app.route("/session/", methods=["POST"])
def update_session():
  """
  Endpoint for updating a user's session
  """
  pass

@app.route("/secret/", methods=["GET"])
def secret_message():
  """
  Endpoint for verifying a session token and returning a secret message
  """
  pass

@app.route("/logout/", methods=["POST"])
def logout():
  """
  Endpoint for logging out a user
  """
  pass





if __name__ == "__main__":
  app.run(host="0.0.0.0", port=8000, debug=True)  