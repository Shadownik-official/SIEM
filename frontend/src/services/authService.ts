import { jwtDecode } from 'jwt-decode';

interface LoginCredentials {
  username: string;
  password: string;
}

interface AuthResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  username: string;
}

class AuthService {
  private static BASE_URL = 'http://localhost:8000';

  private static logRequest(message: string, data?: any) {
    console.group('%c[AuthService] Request', 'color: blue; font-weight: bold');
    console.log(message);
    if (data) {
      console.log('Request Details:', JSON.stringify(data, null, 2));
    }
    console.groupEnd();
  }

  private static logResponse(message: string, data?: any) {
    console.group('%c[AuthService] Response', 'color: green; font-weight: bold');
    console.log(message);
    if (data) {
      console.log('Response Details:', JSON.stringify(data, null, 2));
    }
    console.groupEnd();
  }

  private static logError(message: string, error?: any) {
    console.group('%c[AuthService] Error', 'color: red; font-weight: bold');
    console.error(message);
    
    if (error instanceof Error) {
      console.error('Error Name:', error.name);
      console.error('Error Message:', error.message);
      console.error('Error Stack:', error.stack);
    }
    
    if (error) {
      console.error('Full Error Object:', error);
    }
    
    console.groupEnd();
  }

  static async login(credentials: LoginCredentials): Promise<AuthResponse> {
    this.logRequest('Attempting login', {
      username: credentials.username,
      passwordLength: credentials.password.length
    });

    try {
      const formData = new URLSearchParams();
      formData.append('username', credentials.username);
      formData.append('password', credentials.password);

      console.log('%c[AuthService] Sending Request', 'color: purple', {
        url: `${this.BASE_URL}/token`,
        method: 'POST',
        body: Object.fromEntries(formData)
      });

      const response = await fetch(`${this.BASE_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        body: formData
      });

      console.log('%c[AuthService] Raw Response', 'color: orange', {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries())
      });

      // Comprehensive error handling
      if (!response.ok) {
        const errorText = await response.text();
        const errorDetails = {
          status: response.status,
          statusText: response.statusText,
          errorText
        };
        
        this.logError('Login request failed', errorDetails);

        // Extremely detailed error handling
        switch (response.status) {
          case 401:
            throw new Error('Authentication failed: Invalid credentials');
          case 403:
            throw new Error('Access denied: Insufficient permissions');
          case 500:
            throw new Error('Server error: Please try again later');
          case 503:
            throw new Error('Service unavailable: Backend might be down');
          default:
            throw new Error(`HTTP error: ${response.status} - ${errorText || 'Unknown error'}`);
        }
      }

      // Strict content type validation
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        throw new Error('Invalid response: Expected JSON content type');
      }

      // Safe JSON parsing with error handling
      let data: AuthResponse;
      try {
        data = await response.json();
      } catch (parseError) {
        this.logError('JSON Parsing Error', parseError);
        throw new Error('Failed to parse authentication response');
      }
      
      this.logResponse('Parsed response', data);

      // Comprehensive token validation
      if (!data) {
        throw new Error('Empty authentication response');
      }

      if (!data.access_token) {
        this.logError('Missing access token', data);
        throw new Error('Authentication failed: Access token is missing');
      }

      // Advanced JWT validation
      try {
        const decodedToken = jwtDecode(data.access_token);
        
        // Validate token claims
        if (!decodedToken.sub) {
          throw new Error('Invalid token: Missing subject');
        }

        // Check token expiration
        if (decodedToken.exp && decodedToken.exp * 1000 < Date.now()) {
          throw new Error('Token has expired');
        }

        console.log('%c[AuthService] Token Validation', 'color: green', {
          subject: decodedToken.sub,
          expiration: decodedToken.exp 
            ? new Date(decodedToken.exp * 1000).toISOString() 
            : 'No expiration'
        });
      } catch (decodeError) {
        this.logError('JWT Decoding Error', decodeError);
        throw new Error('Invalid JWT token structure');
      }

      // Secure token storage
      try {
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('username', data.username);
        localStorage.setItem('token_type', data.token_type);
        localStorage.setItem('token_expires', 
          (Date.now() + data.expires_in * 1000).toString()
        );
      } catch (storageError) {
        this.logError('Token Storage Error', storageError);
        throw new Error('Failed to store authentication credentials');
      }

      return data;

    } catch (error: any) {
      this.logError('Authentication Process Error', error);
      
      // Comprehensive error handling
      if (error instanceof TypeError) {
        console.error('Network Error:', error.message);
        throw new Error('Network error: Unable to connect to authentication service');
      }
      
      throw error;
    }
  }

  static logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('token_type');
    localStorage.removeItem('token_expires');
  }

  static getToken(): string | null {
    const token = localStorage.getItem('token');
    const expiresAt = localStorage.getItem('token_expires');

    // Detailed token validation logging
    console.group('Token Validation');
    console.log('Stored Token:', !!token);
    console.log('Expiration:', expiresAt ? new Date(parseInt(expiresAt)).toISOString() : 'Not set');

    // Check if token is expired
    if (token && expiresAt) {
      const isExpired = parseInt(expiresAt) < Date.now();
      console.log('Is Expired:', isExpired);
      
      if (isExpired) {
        console.log('Token expired, logging out');
        this.logout();
        console.groupEnd();
        return null;
      }
    }

    console.groupEnd();
    return token;
  }

  static getAuthHeader(): Record<string, string> {
    const token = this.getToken();
    const tokenType = localStorage.getItem('token_type') || 'Bearer';
    
    return token 
      ? { 'Authorization': `${tokenType} ${token}` } 
      : {};
  }

  static getUsername(): string | null {
    return localStorage.getItem('username');
  }

  static isAuthenticated(): boolean {
    return !!this.getToken();
  }
}

export default AuthService;
