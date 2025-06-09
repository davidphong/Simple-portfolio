import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import useAuthStore from '../store/authStore';
import './AuthPages.css';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { login, loading, error, clearError } = useAuthStore();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    clearError();
    
    if (!email || !password) {
      return;
    }
    
    const success = await login(email, password);
    if (success) {
      navigate('/profile-settings');
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-sidebar">
        <div className="auth-sidebar-content">
          <h1>Easy Portfolio for Developer</h1>
          <p>
            As a web developer, having a portfolio is essential for showcasing your technical skills and attracting potential clients. A portfolio is a museum of your work, with past tech stacks, case studies, and your work history.
          </p>
        </div>
      </div>
      <div className="auth-main">
        <div className="auth-logo">
          <div className="logo-icon"></div>
          <span>DevPort</span>
        </div>
        
        <div className="auth-form-container">
          <h1>Login to account</h1>
          <p className="auth-subtitle">Enter your credentials to access your account</p>

          <div className="auth-github">
            <button className="btn btn-github">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path fillRule="evenodd" clipRule="evenodd" d="M10 0C4.477 0 0 4.477 0 10C0 14.42 2.865 18.17 6.839 19.49C7.339 19.58 7.52 19.27 7.52 19C7.52 18.73 7.512 18.15 7.508 17.31C4.726 17.91 4.139 15.97 4.139 15.97C3.685 14.81 3.029 14.5 3.029 14.5C2.121 13.88 3.098 13.9 3.098 13.9C4.101 13.97 4.629 14.93 4.629 14.93C5.521 16.45 6.969 16.02 7.54 15.76C7.631 15.11 7.889 14.67 8.175 14.42C5.955 14.17 3.62 13.31 3.62 9.47C3.62 8.39 4.01 7.5 4.649 6.82C4.546 6.56 4.203 5.55 4.747 4.15C4.747 4.15 5.587 3.88 7.497 5.17C8.31 4.95 9.15 4.84 9.99 4.836C10.83 4.84 11.67 4.95 12.483 5.17C14.393 3.88 15.233 4.15 15.233 4.15C15.777 5.55 15.434 6.56 15.331 6.82C15.97 7.5 16.36 8.39 16.36 9.47C16.36 13.32 14.025 14.17 11.805 14.42C12.15 14.72 12.463 15.33 12.463 16.26C12.463 17.6 12.453 18.64 12.453 19C12.453 19.27 12.633 19.58 13.139 19.49C17.137 18.17 20 14.417 20 10C20 4.477 15.523 0 10 0Z" fill="white"/>
              </svg>
              Sign in with Github
            </button>
          </div>

          <div className="auth-divider">
            <span>or</span>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            {error && <div className="error-message">{error}</div>}
            
            <div className="form-group">
              <input
                type="email"
                className="form-control"
                placeholder="Enter email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            
            <div className="form-group">
              <input
                type="password"
                className="form-control"
                placeholder="Enter a password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            
            <div className="form-group text-right">
              <Link to="/forgot-password" className="forgot-password">Forgot password</Link>
            </div>
            
            <button 
              type="submit" 
              className="btn btn-primary btn-block" 
              disabled={loading}
            >
              {loading ? 'Signing In...' : 'Sign In'}
            </button>
            
            <div className="auth-footer">
              <p>Not a member? <Link to="/register">Create an account</Link></p>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login; 