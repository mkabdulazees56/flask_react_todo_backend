from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app  


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password


           
    @classmethod
    def get_user_by_email(cls, email):     
        try:
            return current_app.db.users.find_one({"email": email})
        except Exception as e:
            print(f"Error fetching user by username: {e}")
            return None
        
        
    @classmethod
    def create_user(cls, email, username, password):

        try:
            results = current_app.db.users.insert_one({"email": email, "username": username, "password": password})
            print(results)
            if results:
                return results
        except Exception as e:
            print(f"Error creating user: {e}")
            return None
        
    @classmethod
    def check_password(cls, email, password):
        try:
            user = cls.get_user_by_email(email)
            
            if user:
                ispasswordmatched = check_password_hash(user["password"], password)
                if ispasswordmatched:
                    return True
                else:
                    return False
            else:
                return False 
        except Exception as e:
                print(f"Error checking password: {e}")
                return False