from flask import Flask
from flask_cors import CORS
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from app.config import Config
from app.routes.auth_route import auth_bp
from app.routes.todo_route import todo_bp
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

uri = Config.MONGO_URI  

try:
    client = MongoClient(uri)
    db = client.get_database()
    print(f"MongoDB connection successful: {db.name}")
except Exception as e:
    print(f"MongoDB connection failed: {e}")
    client = None

jwt = JWTManager()

def create_app():
    app = Flask(__name__)


    app.config.from_object(Config)

    if client:
        app.mongo_client = client
        app.db = db  
        print("MongoDB client and database attached to Flask app")
    else:
        print("MongoDB client not initialized. Check your connection.")


    jwt.init_app(app)


    
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(todo_bp, url_prefix='/api/v1/todos')

  
    CORS(app, resources={r"/*": {"origins": "*"}})


    return app

