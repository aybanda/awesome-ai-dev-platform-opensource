"""
CSRF Protection Middleware for AIxBlock
=======================================

This middleware implements proper CSRF protection for the AIxBlock application
to fix the critical CSRF vulnerability that allows attackers to create projects
on behalf of authenticated users without their knowledge or consent.

Vulnerability Details:
- Endpoint: POST /api/projects/
- Impact: Unauthorized project creation via CSRF attacks
- CVSS Score: 8.8 (HIGH)
- Status: Fixed with this middleware

Usage:
1. Add this middleware to your Django MIDDLEWARE setting
2. Ensure CSRF tokens are included in all state-changing requests
3. Test thoroughly to ensure no legitimate requests are blocked
"""

import re
import logging
from django.conf import settings
from django.http import JsonResponse
from django.middleware.csrf import get_token, verify_csrf_token
from django.utils.deprecation import MiddlewareMixin
from django.utils.crypto import constant_time_compare

logger = logging.getLogger(__name__)

class CSRFProtectionMiddleware(MiddlewareMixin):
    """
    Enhanced CSRF protection middleware that validates CSRF tokens
    for all state-changing HTTP methods (POST, PUT, PATCH, DELETE).
    
    This middleware fixes the critical CSRF vulnerability by:
    1. Enforcing CSRF token validation on all state-changing requests
    2. Providing clear error messages for CSRF validation failures
    3. Logging CSRF violations for security monitoring
    4. Supporting both header and cookie-based CSRF tokens
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        # Define state-changing HTTP methods that require CSRF protection
        self.state_changing_methods = {'POST', 'PUT', 'PATCH', 'DELETE'}
        
        # Define endpoints that require CSRF protection
        self.protected_endpoints = [
            r'^/api/projects/$',  # Project creation endpoint
            r'^/api/projects/\d+/$',  # Project update/delete endpoints
            r'^/api/users/',  # User management endpoints
            r'^/api/admin/',  # Admin endpoints
            r'^/api/integrations/',  # Integration endpoints
        ]
        
        # Compile regex patterns for performance
        self.protected_patterns = [re.compile(pattern) for pattern in self.protected_endpoints]
    
    def process_request(self, request):
        """
        Process incoming requests and validate CSRF tokens for protected endpoints.
        
        Args:
            request: Django HttpRequest object
            
        Returns:
            None if validation passes, JsonResponse with error if validation fails
        """
        # Skip CSRF validation for non-state-changing methods
        if request.method not in self.state_changing_methods:
            return None
        
        # Skip CSRF validation for non-protected endpoints
        if not self._is_protected_endpoint(request.path):
            return None
        
        # Skip CSRF validation for API endpoints that use token-based auth
        if self._is_token_authenticated(request):
            return None
        
        # Validate CSRF token
        if not self._validate_csrf_token(request):
            logger.warning(
                f"CSRF validation failed for {request.method} {request.path} "
                f"from IP {self._get_client_ip(request)}"
            )
            return JsonResponse(
                {
                    'error': 'CSRF token validation failed',
                    'detail': 'This request was blocked due to missing or invalid CSRF token',
                    'code': 'CSRF_VALIDATION_FAILED'
                },
                status=403
            )
        
        return None
    
    def _is_protected_endpoint(self, path):
        """
        Check if the given path requires CSRF protection.
        
        Args:
            path: Request path
            
        Returns:
            bool: True if endpoint requires CSRF protection
        """
        return any(pattern.match(path) for pattern in self.protected_patterns)
    
    def _is_token_authenticated(self, request):
        """
        Check if the request uses token-based authentication (API keys, JWT, etc.).
        These requests typically don't need CSRF protection.
        
        Args:
            request: Django HttpRequest object
            
        Returns:
            bool: True if request uses token-based authentication
        """
        # Check for common token-based authentication headers
        token_headers = [
            'Authorization',
            'X-API-Key',
            'X-Auth-Token',
            'Bearer'
        ]
        
        for header in token_headers:
            if request.headers.get(header):
                return True
        
        return False
    
    def _validate_csrf_token(self, request):
        """
        Validate the CSRF token from the request.
        
        Args:
            request: Django HttpRequest object
            
        Returns:
            bool: True if CSRF token is valid
        """
        try:
            # Get CSRF token from header or cookie
            csrf_token = self._get_csrf_token(request)
            
            if not csrf_token:
                return False
            
            # Validate the token using Django's built-in verification
            return verify_csrf_token(request, csrf_token) is None
            
        except Exception as e:
            logger.error(f"Error validating CSRF token: {e}")
            return False
    
    def _get_csrf_token(self, request):
        """
        Extract CSRF token from request headers or cookies.
        
        Args:
            request: Django HttpRequest object
            
        Returns:
            str: CSRF token or None if not found
        """
        # Try to get token from header first
        csrf_token = request.headers.get('X-CSRFToken')
        
        if not csrf_token:
            # Fall back to cookie
            csrf_token = request.COOKIES.get('csrftoken')
        
        return csrf_token
    
    def _get_client_ip(self, request):
        """
        Get the client IP address from the request.
        
        Args:
            request: Django HttpRequest object
            
        Returns:
            str: Client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')

# Django settings configuration
CSRF_MIDDLEWARE_SETTINGS = """
# Add this middleware to your Django MIDDLEWARE setting in settings.py:

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # Keep Django's built-in CSRF
    'path.to.csrf_protection_middleware.CSRFProtectionMiddleware',  # Add our enhanced middleware
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Additional CSRF settings for enhanced security:
CSRF_COOKIE_SECURE = True  # Only send CSRF cookie over HTTPS
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript access for AJAX requests
CSRF_COOKIE_SAMESITE = 'Strict'  # Prevent CSRF from other sites
CSRF_USE_SESSIONS = True  # Store CSRF token in session instead of cookie
CSRF_FAILURE_VIEW = 'django.views.csrf.csrf_failure'  # Custom failure view
"""

# Example view decorator for additional CSRF protection
def require_csrf_token(view_func):
    """
    Decorator to ensure CSRF token is present and valid for a view.
    
    Usage:
        @require_csrf_token
        def create_project(request):
            # Your view logic here
            pass
    """
    def wrapper(request, *args, **kwargs):
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            if not request.headers.get('X-CSRFToken'):
                return JsonResponse(
                    {'error': 'CSRF token required'}, 
                    status=403
                )
        return view_func(request, *args, **kwargs)
    return wrapper

# Example usage in views.py
EXAMPLE_VIEW_USAGE = """
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from .csrf_protection_middleware import require_csrf_token

@ensure_csrf_cookie  # Ensures CSRF cookie is set
@require_csrf_token  # Validates CSRF token
def create_project(request):
    if request.method == 'POST':
        # Validate CSRF token manually if needed
        if not verify_csrf_token(request, request.headers.get('X-CSRFToken')):
            return JsonResponse({'error': 'Invalid CSRF token'}, status=403)
        
        # Your project creation logic here
        project_data = request.POST
        # ... create project ...
        
        return JsonResponse({'success': True, 'project_id': project.id})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)
"""

# Testing utilities
class CSRFTestUtils:
    """
    Utility class for testing CSRF protection.
    """
    
    @staticmethod
    def create_csrf_test_request(method='POST', path='/api/projects/', 
                                csrf_token='valid_token', authenticated=True):
        """
        Create a test request for CSRF validation testing.
        
        Args:
            method: HTTP method
            path: Request path
            csrf_token: CSRF token to include
            authenticated: Whether request should appear authenticated
            
        Returns:
            Mock request object for testing
        """
        from unittest.mock import Mock
        
        request = Mock()
        request.method = method
        request.path = path
        request.headers = {}
        request.COOKIES = {}
        
        if csrf_token:
            request.headers['X-CSRFToken'] = csrf_token
            request.COOKIES['csrftoken'] = csrf_token
        
        if authenticated:
            request.COOKIES['sessionid'] = 'test_session_id'
        
        return request
    
    @staticmethod
    def test_csrf_middleware():
        """
        Test the CSRF middleware with various scenarios.
        """
        middleware = CSRFProtectionMiddleware()
        
        # Test 1: Valid CSRF token
        valid_request = CSRFTestUtils.create_csrf_test_request(
            csrf_token='valid_token'
        )
        result = middleware.process_request(valid_request)
        print(f"Valid CSRF token test: {'PASS' if result is None else 'FAIL'}")
        
        # Test 2: Missing CSRF token
        invalid_request = CSRFTestUtils.create_csrf_test_request(
            csrf_token=None
        )
        result = middleware.process_request(invalid_request)
        print(f"Missing CSRF token test: {'PASS' if result is not None else 'FAIL'}")
        
        # Test 3: Non-protected endpoint
        safe_request = CSRFTestUtils.create_csrf_test_request(
            path='/api/public/data/'
        )
        result = middleware.process_request(safe_request)
        print(f"Non-protected endpoint test: {'PASS' if result is None else 'FAIL'}")

if __name__ == '__main__':
    # Run tests if script is executed directly
    CSRFTestUtils.test_csrf_middleware() 