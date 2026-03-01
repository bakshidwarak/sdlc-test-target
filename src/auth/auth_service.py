import bcrypt
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os

class AuthService:
    def __init__(self):
        self.jwt_secret = os.getenv('JWT_SECRET', 'your-secret-key')
        self.jwt_expiry_hours = 24
    
    def authenticate_user(self, email: str, password: str, users_db: Dict[str, Dict]) -> Optional[Dict[str, Any]]:
        """Authenticate user with email and password"""
        # Find user by email
        user = None
        for user_id, user_data in users_db.items():
            if user_data.get('email') == email:
                user = {'id': user_id, **user_data}
                break
        
        if not user:
            return None
        
        # Verify password
        if not self._verify_password(password, user['password_hash']):
            return None
        
        # Generate JWT token
        token = self._generate_jwt_token(user['id'])
        
        return {
            'user_id': user['id'],
            'email': user['email'],
            'token': token
        }
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False
    
    def _generate_jwt_token(self, user_id: str) -> str:
        """Generate JWT token for user"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=self.jwt_expiry_hours),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password for storage"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')