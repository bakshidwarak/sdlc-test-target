import pytest
from src.auth.auth_service import AuthService

class TestAuthService:
    def setup_method(self):
        self.auth_service = AuthService()
        self.mock_users_db = {
            "user1": {
                "email": "test@example.com",
                "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3bp.Txu.Wr"  # "password123"
            }
        }
    
    def test_authenticate_user_valid_credentials(self):
        """Test successful authentication with valid credentials"""
        result = self.auth_service.authenticate_user(
            "test@example.com", 
            "password123", 
            self.mock_users_db
        )
        
        assert result is not None
        assert result['user_id'] == "user1"
        assert result['email'] == "test@example.com"
        assert 'token' in result
        assert len(result['token']) > 0
    
    def test_authenticate_user_invalid_password(self):
        """Test authentication fails with invalid password"""
        result = self.auth_service.authenticate_user(
            "test@example.com", 
            "wrongpassword", 
            self.mock_users_db
        )
        
        assert result is None
    
    def test_authenticate_user_nonexistent_email(self):
        """Test authentication fails with non-existent email"""
        result = self.auth_service.authenticate_user(
            "nonexistent@example.com", 
            "password123", 
            self.mock_users_db
        )
        
        assert result is None
    
    def test_verify_password_valid(self):
        """Test password verification with valid password"""
        password_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3bp.Txu.Wr"
        
        result = self.auth_service._verify_password("password123", password_hash)
        
        assert result is True
    
    def test_verify_password_invalid(self):
        """Test password verification with invalid password"""
        password_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3bp.Txu.Wr"
        
        result = self.auth_service._verify_password("wrongpassword", password_hash)
        
        assert result is False
    
    def test_generate_jwt_token(self):
        """Test JWT token generation"""
        token = self.auth_service._generate_jwt_token("user123")
        
        assert token is not None
        assert len(token) > 0
        assert isinstance(token, str)
    
    def test_hash_password(self):
        """Test password hashing"""
        password = "testpassword"
        hashed = AuthService.hash_password(password)
        
        assert hashed is not None
        assert len(hashed) > 0
        assert hashed != password
        assert hashed.startswith('$2b$')