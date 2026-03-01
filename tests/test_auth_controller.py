import pytest
import json
from unittest.mock import patch, MagicMock
from src.auth.auth_controller import app, validate_email, validate_login_request

class TestAuthController:
    def setup_method(self):
        self.app = app.test_client()
        self.app.testing = True
    
    def test_login_valid_credentials(self):
        """Test successful login with valid credentials"""
        login_data = {
            "email": "test@example.com",
            "password": "password123"
        }
        
        response = self.app.post('/auth/login', 
                               data=json.dumps(login_data),
                               content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'token' in data
        assert 'user_id' in data
        assert 'email' in data
        assert data['email'] == "test@example.com"
    
    def test_login_invalid_credentials(self):
        """Test login fails with invalid credentials"""
        login_data = {
            "email": "test@example.com",
            "password": "wrongpassword"
        }
        
        response = self.app.post('/auth/login',
                               data=json.dumps(login_data),
                               content_type='application/json')
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
        assert data['error'] == 'Invalid credentials'
    
    def test_login_missing_email(self):
        """Test login fails with missing email"""
        login_data = {
            "password": "password123"
        }
        
        response = self.app.post('/auth/login',
                               data=json.dumps(login_data),
                               content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert data['error'] == 'Email is required'
    
    def test_login_missing_password(self):
        """Test login fails with missing password"""
        login_data = {
            "email": "test@example.com"
        }
        
        response = self.app.post('/auth/login',
                               data=json.dumps(login_data),
                               content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert data['error'] == 'Password is required'
    
    def test_login_invalid_email_format(self):
        """Test login fails with invalid email format"""
        login_data = {
            "email": "invalid-email",
            "password": "password123"
        }
        
        response = self.app.post('/auth/login',
                               data=json.dumps(login_data),
                               content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert data['error'] == 'Invalid email format'
    
    def test_validate_email_valid(self):
        """Test email validation with valid email"""
        assert validate_email("test@example.com") is True
        assert validate_email("user.name+tag@domain.co.uk") is True
    
    def test_validate_email_invalid(self):
        """Test email validation with invalid email"""
        assert validate_email("invalid-email") is False
        assert validate_email("@domain.com") is False
        assert validate_email("user@") is False
    
    def test_validate_login_request_valid(self):
        """Test login request validation with valid data"""
        data = {
            "email": "test@example.com",
            "password": "password123"
        }
        
        is_valid, error = validate_login_request(data)
        
        assert is_valid is True
        assert error == ""
    
    def test_validate_login_request_short_password(self):
        """Test login request validation with short password"""
        data = {
            "email": "test@example.com",
            "password": "123"
        }
        
        is_valid, error = validate_login_request(data)
        
        assert is_valid is False
        assert error == "Password must be at least 6 characters"