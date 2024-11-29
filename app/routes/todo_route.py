from flask import Blueprint, jsonify, request
from app.models.todo import Todo
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from flask_jwt_extended import get_jwt

todo_bp = Blueprint('todo', __name__)

@todo_bp.route('/get-todos', methods=['GET'])
@jwt_required()
def get_todos():
    user_id = get_jwt_identity()  # Retrieve the identity (user ID)
    
    

    todos = Todo.get_todos(user_id)

    todo_list = [{"todo_id": todo["todo_id"], "task": todo["task"], "completed": todo["completed"], "created_at": todo["created_at"]} for todo in todos]
    return jsonify({"todo_list": todo_list}), 200

@todo_bp.route('/add-todo', methods=['POST'])
@jwt_required()
def create_todo():
    try:
        user_id = get_jwt_identity()  
              
        data = request.get_json()

        newtodo = data.get("newtodo")
        task = newtodo.get("task")
        todo_id = newtodo.get("todo_id")
        deleted = newtodo.get("deleted")

        created_at = datetime.now()

        if not task:
            return jsonify({"message": "Task is required"}), 400

        Todo.create_todo(task, user_id, todo_id, created_at, deleted)

        return jsonify({"message": "Todo created successfully"}), 201
    except Exception as e:
        print(f"Error creating todo: {e}")
        return jsonify({"message": "Error creating todo"}), 500

@todo_bp.route('/update/<todo_id>', methods=['PUT'])
@jwt_required()
def update_todo(todo_id):
    try:
        data = request.get_json()

        task = data.get("editedtask")
        print(task)

        if not task:
            return jsonify({"message": "Task is required"}), 400

        results = Todo.update_todo(task, todo_id)
        print(results)

        if results > 0:
            return jsonify({"message": "Todo updated successfully"}), 200
        else:
            return jsonify({"message": "Todo not found"}), 404

    except Exception as e:
        print(f"Error updating todo: {e}")  


@todo_bp.route('/delete/<todo_id>', methods=['DELETE'])
@jwt_required()
def delete_todo(todo_id):
    try:
        results  = Todo.delete_todo(todo_id)
    
        if results > 0:
            return jsonify({"message": "Todo deleted successfully"}), 200
        else:
            return jsonify({"message": "Todo not found"}), 404
    except Exception as e:
        print(f"Error deleting todo: {e}")
        return jsonify({"message": "Error deleting todo"}), 500

    
    

@todo_bp.route("/completed/<todo_id>", methods=["POST"])
@jwt_required()
def mark_as_completed(todo_id):
    try:
        data = request.get_json()
        
        isCompleted = data.get("isCompleted")
        
        results =Todo.mark_as_completed( todo_id, isCompleted)
        if results > 0:
            return jsonify({"message": "Todo marked as completed"}), 200
    except Exception as e:
        return jsonify({"message": "Error marking todo as completed"}), 500