import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import useAuthStore from '../store/authStore';
import './Header.css';

const Header = () => {
  const { user, logout, isAuthenticated } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  
  const handleLogout = () => {
    logout();
    navigate('/login');
  };
  
  const toggleDropdown = () => {
    setDropdownOpen(!dropdownOpen);
  };
  
  const closeDropdown = () => {
    setDropdownOpen(false);
  };
  
  // Check if current route is active
  const isActive = (path) => {
    return location.pathname === path;
  };
  
  return (
    <header className="header">
      <div className="container">
        <div className="header-content">
          <Link to="/" className="logo">
            <div className="logo-icon"></div>
            <span>BlueCyber</span>
          </Link>
          
          {isAuthenticated() && (
            <div className="main-nav">
              <Link to="/profile-settings" className={`nav-link ${isActive('/profile-settings') ? 'active' : ''}`}>
                Profile
              </Link>
              <Link to="/projects-settings" className={`nav-link ${isActive('/projects-settings') ? 'active' : ''}`}>
                Projects
              </Link>
              <Link to={`/portfolio/${user?.id}`} className={`nav-link ${isActive(`/portfolio/${user?.id}`) ? 'active' : ''}`}>
                Portfolio
              </Link>
            </div>
          )}
          
          <nav className="nav">
            {isAuthenticated() ? (
              <>
                <div className="dropdown">
                  <div className="user-profile" onClick={toggleDropdown}>
                    <div className="user-avatar">
                      {user?.name?.charAt(0) || 'U'}
                    </div>
                  </div>
                  {dropdownOpen && (
                    <>
                      <div className="dropdown-backdrop" onClick={closeDropdown}></div>
                      <div className="dropdown-menu">
                        <div className="dropdown-header">
                          <div className="user-info">
                            <div className="user-name">{user?.name}</div>
                            <div className="user-email">{user?.email}</div>
                          </div>
                        </div>
                        <button onClick={handleLogout} className="dropdown-item text-danger">
                          <i className="icon-logout"></i>
                          Log out
                        </button>
                      </div>
                    </>
                  )}
                </div>
              </>
            ) : (
              <Link to="/login" className="btn btn-primary">
                Login
              </Link>
            )}
          </nav>
        </div>
      </div>
    </header>
  );
};

export default Header; 