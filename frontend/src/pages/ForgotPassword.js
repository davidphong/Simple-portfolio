import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { forgotPassword } from '../utils/api';
import './AuthPages.css';

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      await forgotPassword(email);
      setSuccess(true);
    } catch (error) {
      setError(error.response?.data?.error || 'An error occurred. Please try again.');
    } finally {
      setLoading(false);
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
          <h1>Forgot password</h1>
          <p className="auth-subtitle">We'll email you instructions to reset your password</p>

          {!success ? (
            <form className="auth-form" onSubmit={handleSubmit}>
              {error && <div className="error-message">{error}</div>}
              
              <div className="form-group">
                <input
                  type="email"
                  className="form-control"
                  placeholder="Enter a password"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              
              <button 
                type="submit" 
                className="btn btn-primary btn-block" 
                disabled={loading}
              >
                {loading ? 'Sending...' : 'Reset Password'}
              </button>
              
              <div className="auth-footer">
                <p><Link to="/login">Back to login</Link></p>
              </div>
            </form>
          ) : (
            <div className="success-message">
              <p>If the email is registered, you will receive instructions to reset your password.</p>
              <div className="auth-footer">
                <p><Link to="/login">Back to login</Link></p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword; 