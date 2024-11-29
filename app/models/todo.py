from flask import current_app  
from datetime import datetime

class Todo:
    def __init__(self, task, user_id):
        self.task = task
        self.user_id = user_id
        self.completed = False
        self.created_at = datetime.now()

    @classmethod
    def create_todo(cls, task, user_id, todo_id, created_at, deleted):
        try:
            results = current_app.db.todos.insert_one({"task": task, "user_id":  user_id, "deleted":deleted, "todo_id" :todo_id, "completed": False, "created_at": created_at})
            return results
        except Exception as e:
            print(f"Error creating todo: {e}")
            return "Error creating todo"

    @classmethod
    def get_todos(cls, user_id):
        try:
            return current_app.db.todos.find({"user_id": user_id, "deleted": False})
        except Exception as e:
            print(f"Error fetching todos: {e}")
            return "Error featching todo"

    @classmethod
    def update_todo(cls, task, todo_id):
        try:
            results = current_app.db.todos.update_one({"todo_id": todo_id}, {"$set": {"task": task}})

            n_modified = results.raw_result['nModified']
            return n_modified;
        except Exception as e:
            print(f"Error updating todo: {e}")
            return "Error updating todo"
    
    @classmethod
    def mark_as_completed(cls, todo_id, completed):
        try:
            results = current_app.db.todos.update_one({"todo_id": todo_id}, {"$set": {"completed": completed}})

            n_modified = results.raw_result['nModified']          
            return n_modified;
        except Exception as e:
            print(f"Error updating todo: {e}")
            return "Error updating todo"
        
    @classmethod
    def delete_todo(cls, todo_Id):
     
        try:
            results = current_app.db.todos.update_one({"todo_id": todo_Id}, {"$set": {"deleted": True}})

            n_modified = results.raw_result['nModified']
            print(n_modified)           
            return n_modified;
        except Exception as e:
            print(f"Error deleting todo: {e}")
            return "Error updating todo"
            