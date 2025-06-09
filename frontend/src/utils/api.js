import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:7331/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add a request interceptor to add the auth token to every request if available
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      console.log('Adding token to request:', token);
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add a response interceptor to handle common errors
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.log('API Error:', error.response?.status, error.response?.data);
    
    // Handle specific error codes
    if (error.response) {
      // Handle 401 (Unauthorized)
      if (error.response.status === 401) {
        console.log('Unauthorized access, redirecting to login');
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/login';
      }
      
      // Handle 422 (Unprocessable Entity)
      if (error.response.status === 422) {
        console.log('Validation error:', error.response.data);
      }
    }
    
    return Promise.reject(error);
  }
);

export const login = (email, password) => {
  return api.post('/user/login', { email, password });
};

export const register = (email, password, name) => {
  return api.post('/user/signup', { email, password, name });
};

export const forgotPassword = (email) => {
  return api.post('/user/forgot-password', { email });
};

export const resetPassword = (token, password) => {
  return api.post('/user/reset-password', { token, password });
};

export const getProfile = () => {
  return api.get('/user/profile');
};

export const updateProfile = (profileData) => {
  // Check if profileData is FormData or regular JSON
  const isFormData = profileData instanceof FormData;
  
  // Set the correct headers for FormData (multipart/form-data) or JSON
  const headers = isFormData ? 
    { 'Content-Type': 'multipart/form-data' } : 
    { 'Content-Type': 'application/json' };
  
  return api.put('/user/profile', profileData, { headers });
};

export const getProjects = () => {
  return api.get('/user/projects');
};

export const addProject = (projectData) => {
  // Check if projectData is FormData or regular JSON
  const isFormData = projectData instanceof FormData;
  
  // Set the correct headers for FormData (multipart/form-data) or JSON
  const headers = isFormData ? 
    { 'Content-Type': 'multipart/form-data' } : 
    { 'Content-Type': 'application/json' };
  
  return api.post('/user/projects', projectData, { headers });
};

export const updateProject = (projectId, projectData) => {
  // Check if projectData is FormData or regular JSON
  const isFormData = projectData instanceof FormData;
  
  // Set the correct headers for FormData (multipart/form-data) or JSON
  const headers = isFormData ? 
    { 'Content-Type': 'multipart/form-data' } : 
    { 'Content-Type': 'application/json' };
  
  return api.put(`/user/projects/${projectId}`, projectData, { headers });
};

export const deleteProject = (projectId) => {
  return api.delete(`/user/projects/${projectId}`);
};

export const getPortfolio = (userId) => {
  return api.get(`/portfolio/${userId}`);
};

export const sendContactMessage = (userId, messageData) => {
  return api.post('/contact', { user_id: userId, ...messageData });
};

export default api; 