export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  permissions?: string[];
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface Session {
  user: User;
  expires?: Date;
} 