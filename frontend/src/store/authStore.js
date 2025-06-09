import { create } from 'zustand';
import { login as apiLogin, register as apiRegister } from '../utils/api';

const useAuthStore = create((set) => ({
  token: localStorage.getItem('token') || null,
  user: JSON.parse(localStorage.getItem('user')) || null,
  loading: false,
  error: null,
  
  login: async (email, password) => {
    set({ loading: true, error: null });
    try {
      const response = await apiLogin(email, password);
      console.log('Login response:', response.data);
      
      const token = response.data.token;
      const user = response.data.user;
      
      if (!token) {
        console.error('No token received in login response');
        set({ 
          error: 'Authentication failed: No token received',
          loading: false 
        });
        return false;
      }
      
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(user));
      
      set({ token, user, loading: false });
      return true;
    } catch (error) {
      console.error("Login error:", error);
      set({ 
        error: error.response?.data?.error || 'Login failed',
        loading: false 
      });
      return false;
    }
  },
  
  register: async (email, password, name) => {
    set({ loading: true, error: null });
    try {
      const response = await apiRegister(email, password, name);
      const { token, user } = response.data;
      
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(user));
      
      set({ token, user, loading: false });
      return true;
    } catch (error) {
      console.error("Registration error:", error);
      set({ 
        error: error.response?.data?.error || 'Registration failed',
        loading: false 
      });
      return false;
    }
  },
  
  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    set({ token: null, user: null });
  },
  
  clearError: () => {
    set({ error: null });
  },
  
  isAuthenticated: () => {
    return !!localStorage.getItem('token');
  }
}));

export default useAuthStore; 