import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { resetPassword } from '../utils/api';
import './AuthPages.css';

const ResetPassword = () => {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [token, setToken] = useState('');
  const [passwordRequirements, setPasswordRequirements] = useState({
    lowercase: false,
    special: false,
    uppercase: false,
    length: false,
    number: false
  });
  
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const tokenParam = searchParams.get('token');
    
    if (!tokenParam) {
      setError('Invalid or missing reset token');
    } else {
      setToken(tokenParam);
    }
  }, [location.search]);

  const checkPasswordRequirements = (password) => {
    setPasswordRequirements({
      lowercase: /[a-z]/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
      uppercase: /[A-Z]/.test(password),
      length: password.length >= 8,
      number: /[0-9]/.test(password)
    });
  };

  const handlePasswordChange = (e) => {
    const newPassword = e.target.value;
    setPassword(newPassword);
    checkPasswordRequirements(newPassword);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    // Check if passwords match
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }
    
    // Check if all password requirements are met
    const allRequirementsMet = Object.values(passwordRequirements).every(req => req);
    if (!allRequirementsMet) {
      setError('Password does not meet all requirements');
      setLoading(false);
      return;
    }
    
    try {
      await resetPassword(token, password);
      setSuccess(true);
      
      // Redirect to login after a short delay
      setTimeout(() => {
        navigate('/login');
      }, 3000);
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
          <h1>Choose new password</h1>
          <p className="auth-subtitle">Enter your new password and you're all set.</p>

          {!success ? (
            <form className="auth-form" onSubmit={handleSubmit}>
              {error && <div className="error-message">{error}</div>}
              
              <div className="form-group">
                <input
                  type="password"
                  className="form-control"
                  placeholder="Enter a password"
                  value={password}
                  onChange={handlePasswordChange}
                  required
                />
              </div>
              
              <div className="form-group">
                <input
                  type="password"
                  className="form-control"
                  placeholder="Re-enter a password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                />
              </div>
              
              <div className="password-requirements">
                <div className={`requirement ${passwordRequirements.lowercase ? 'met' : ''}`}>
                  <div className="requirement-icon"></div>
                  <span>one lower case character</span>
                </div>
                <div className={`requirement ${passwordRequirements.special ? 'met' : ''}`}>
                  <div className="requirement-icon"></div>
                  <span>one special character</span>
                </div>
                <div className={`requirement ${passwordRequirements.uppercase ? 'met' : ''}`}>
                  <div className="requirement-icon"></div>
                  <span>one uppercase character</span>
                </div>
                <div className={`requirement ${passwordRequirements.length ? 'met' : ''}`}>
                  <div className="requirement-icon"></div>
                  <span>8 character minium</span>
                </div>
                <div className={`requirement ${passwordRequirements.number ? 'met' : ''}`}>
                  <div className="requirement-icon"></div>
                  <span>one number</span>
                </div>
              </div>
              
              <button 
                type="submit" 
                className="btn btn-primary btn-block" 
                disabled={loading || !token}
              >
                {loading ? 'Resetting...' : 'Reset Password'}
              </button>
            </form>
          ) : (
            <div className="success-message">
              <p>Your password has been successfully reset. You will be redirected to login shortly.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ResetPassword; 