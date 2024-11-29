from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from app.models.user import User

auth_bp = Blueprint('auth', __name__)

# @auth_bp.route('/register', methods=['POST'])
# def register():
#     data = request.get_json()

#     email = data.get("email")
#     username = data.get("username")
#     password = data.get("password")

#     existinguser = User.get_user_by_email(email)
#     if existinguser:
#         return jsonify({"message": "User already exists"}), 400
    
#     hashed_password = generate_password_hash(password)

#     User.create_user(email, username, hashed_password)

#     return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"message": "Invalid request, no data provided"}), 400

        email = data.get("email")
        username = data.get("username")
        password = data.get("password")

        if not email or not username or not password:
            return jsonify({"message": "Missing required fields"}), 400

        existinguser = User.get_user_by_email(email)
        if existinguser:
            return jsonify({"message": "User already exists"}), 400

        hashed_password = generate_password_hash(password)

        User.create_user(email, username, hashed_password)

        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        return jsonify({"message": "An error occurred during registration", "error": str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        print(data)

        email = data.get("email")
        password = data.get("password")

        user = User.get_user_by_email(email)
        print(user)
    
        if not user:
            return jsonify({"message": "User not found"}), 401

        ispasswordmatched = User.check_password(email, password)
     
        if not ispasswordmatched:
            return jsonify({"message": "Invalid password"}), 401
        
        access_token = create_access_token(
            identity=str(user["_id"]), 
            additional_claims={"username": user["username"]})

        return jsonify({"access_token": access_token}), 200
    except Exception as e:
        print(f"Error logging in: {e}")
        return jsonify({"message": "Error logging in"}), 500
        