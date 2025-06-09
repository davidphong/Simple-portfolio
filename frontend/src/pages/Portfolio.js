import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { getPortfolio, sendContactMessage } from '../utils/api';
import './Portfolio.css';

const Portfolio = () => {
  const { userId } = useParams();
  const [portfolio, setPortfolio] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showContactModal, setShowContactModal] = useState(false);
  const [contactForm, setContactForm] = useState({
    name: '',
    email: '',
    message: ''
  });
  const [sendingMessage, setSendingMessage] = useState(false);
  const [messageSent, setMessageSent] = useState(false);
  
  useEffect(() => {
    const fetchPortfolio = async () => {
      try {
        setLoading(true);
        const response = await getPortfolio(userId);
        setPortfolio(response.data);
        setError(null);
      } catch (error) {
        setError('Failed to load portfolio');
        console.error(error);
      } finally {
        setLoading(false);
      }
    };
    
    if (userId) {
      fetchPortfolio();
    }
  }, [userId]);

  const handleContactChange = (e) => {
    const { name, value } = e.target;
    setContactForm({ ...contactForm, [name]: value });
  };

  const handleContactSubmit = async (e) => {
    e.preventDefault();
    
    try {
      setSendingMessage(true);
      await sendContactMessage(userId, contactForm);
      setMessageSent(true);
      setContactForm({
        name: '',
        email: '',
        message: ''
      });
      
      // Close modal after a delay
      setTimeout(() => {
        setShowContactModal(false);
        setMessageSent(false);
      }, 3000);
    } catch (error) {
      setError('Failed to send message');
      console.error(error);
    } finally {
      setSendingMessage(false);
    }
  };

  if (loading) {
    return <div className="portfolio-loading">Loading portfolio...</div>;
  }

  if (error || !portfolio) {
    return <div className="portfolio-error">Error: {error || 'Portfolio not found'}</div>;
  }

  return (
    <div className="portfolio-page">
      <div className="portfolio-header">
        <div className="container">
          <div className="portfolio-profile">
            <div className="portfolio-avatar">
              {portfolio.user.profile_image ? (
                <img 
                  src={`${process.env.REACT_APP_API_URL || 'http://localhost:7331'}/uploads/${portfolio.user.profile_image}`} 
                  alt={portfolio.user.name} 
                />
              ) : (
                portfolio.user.name?.charAt(0) || 'U'
              )}
            </div>
            <div className="portfolio-info">
              <h1 className="portfolio-name">{portfolio.user.name}</h1>
              <p className="portfolio-job-title">{portfolio.user.job_title}</p>
              <div className="portfolio-bio">
                {portfolio.user.bio}
              </div>
              <button 
                className="btn btn-primary contact-btn" 
                onClick={() => setShowContactModal(true)}
              >
                Contact
              </button>
            </div>
          </div>
        </div>
      </div>
      
      <div className="portfolio-content">
        <div className="container">
          <h2 className="portfolio-section-title">Projects</h2>
          
          <div className="portfolio-projects">
            {portfolio.projects.length === 0 ? (
              <div className="no-projects">No projects to display</div>
            ) : (
              portfolio.projects.map(project => (
                <div className="portfolio-project" key={project.id}>
                  <div className="project-image">
                    {project.image ? (
                      <img 
                        src={`${process.env.REACT_APP_API_URL || 'http://localhost:7331'}/uploads/${project.image}`} 
                        alt={project.name} 
                      />
                    ) : (
                      <div className="project-image-placeholder"></div>
                    )}
                  </div>
                  <div className="project-content">
                    <h3 className="project-title">{project.name}</h3>
                    <p className="project-description">{project.description}</p>
                    <div className="project-links">
                      {project.demo_url && (
                        <a 
                          href={project.demo_url} 
                          target="_blank" 
                          rel="noopener noreferrer" 
                          className="project-link demo-link"
                        >
                          Demo URL
                          <span className="external-icon"></span>
                        </a>
                      )}
                      {project.repo_url && (
                        <a 
                          href={project.repo_url} 
                          target="_blank" 
                          rel="noopener noreferrer" 
                          className="project-link repo-link"
                        >
                          Repository URL
                          <span className="external-icon"></span>
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
      
      <div className="portfolio-footer">
        <div className="container">
          <p>power by <span className="footer-logo">DevPort</span></p>
        </div>
      </div>
      
      {/* Contact Modal */}
      {showContactModal && (
        <div className="modal-backdrop">
          <div className="modal">
            <div className="modal-header">
              <h2 className="modal-title">Contact {portfolio.user.name}</h2>
              <button 
                className="modal-close" 
                onClick={() => setShowContactModal(false)}
              >
                &times;
              </button>
            </div>
            <div className="modal-body">
              {messageSent ? (
                <div className="success-message">
                  Your message has been sent successfully!
                </div>
              ) : (
                <form onSubmit={handleContactSubmit}>
                  <div className="form-group">
                    <label>Your Name</label>
                    <input
                      type="text"
                      className="form-control"
                      name="name"
                      value={contactForm.name}
                      onChange={handleContactChange}
                      required
                    />
                  </div>
                  
                  <div className="form-group">
                    <label>Your Email</label>
                    <input
                      type="email"
                      className="form-control"
                      name="email"
                      value={contactForm.email}
                      onChange={handleContactChange}
                      required
                    />
                  </div>
                  
                  <div className="form-group">
                    <label>Message</label>
                    <textarea
                      className="form-control"
                      name="message"
                      value={contactForm.message}
                      onChange={handleContactChange}
                      rows="4"
                      required
                    ></textarea>
                  </div>
                  
                  <div className="modal-footer">
                    <button 
                      type="button" 
                      className="btn btn-secondary" 
                      onClick={() => setShowContactModal(false)}
                    >
                      Cancel
                    </button>
                    <button 
                      type="submit" 
                      className="btn btn-primary" 
                      disabled={sendingMessage}
                    >
                      {sendingMessage ? 'Sending...' : 'Send Message'}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Portfolio; 