from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from typing import Dict, Any
from .auth_service import AuthService

app = Flask(__name__)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Mock user database - in production this would be a real database
USERS_DB = {
    "user1": {
        "email": "test@example.com",
        "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3bp.Txu.Wr"  # "password123"
    },
    "user2": {
        "email": "admin@example.com", 
        "password_hash": "$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi"  # "admin456"
    }
}

auth_service = AuthService()

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_login_request(data: Dict[str, Any]) -> tuple[bool, str]:
    """Validate login request data"""
    if not data:
        return False, "Request body is required"
    
    email = data.get('email')
    password = data.get('password')
    
    if not email:
        return False, "Email is required"
    
    if not password:
        return False, "Password is required"
    
    if not validate_email(email):
        return False, "Invalid email format"
    
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    
    return True, ""

@app.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """Authenticate user with email and password"""
    try:
        # Get request data
        data = request.get_json()
        
        # Validate request
        is_valid, error_message = validate_login_request(data)
        if not is_valid:
            return jsonify({'error': error_message}), 400
        
        # Authenticate user
        result = auth_service.authenticate_user(
            data['email'], 
            data['password'], 
            USERS_DB
        )
        
        if not result:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Return success response
        return jsonify({
            'token': result['token'],
            'user_id': result['user_id'],
            'email': result['email']
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True)