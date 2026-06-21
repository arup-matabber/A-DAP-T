export type AuthState = {
  idToken: string;
  refreshToken?: string;
  expiresAt?: number;
  email?: string;
  displayName?: string;
  uid?: string;
};
