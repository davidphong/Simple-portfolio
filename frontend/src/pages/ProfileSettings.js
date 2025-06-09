import React, { useState, useEffect } from 'react';
import useProfileStore from '../store/profileStore';
import useAuthStore from '../store/authStore';
import Header from '../components/Header';
import './Settings.css';

const ProfileSettings = () => {
  const { profile, fetchProfile, updateProfile, loading, error } = useProfileStore();
  const { isAuthenticated } = useAuthStore();
  const [formData, setFormData] = useState({
    name: '',
    job_title: '',
    bio: '',
    email: ''
  });
  const [success, setSuccess] = useState(false);
  const [imagePreview, setImagePreview] = useState(null);
  const [imageFile, setImageFile] = useState(null);
  
  useEffect(() => {
    if (isAuthenticated()) {
      // Verify if the token actually works
      console.log("Fetching profile with token:", localStorage.getItem('token'));
      fetchProfile().catch(err => {
        console.error("Error fetching profile:", err);
      });
    }
  }, [fetchProfile, isAuthenticated]);
  
  useEffect(() => {
    if (profile) {
      setFormData({
        name: profile.name || '',
        job_title: profile.job_title || '',
        bio: profile.bio || '',
        email: profile.email || ''
      });
      
      if (profile.profile_image) {
        setImagePreview(`${process.env.REACT_APP_API_URL || 'http://localhost:7331'}/uploads/${profile.profile_image}`);
      }
    }
  }, [profile]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setImageFile(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setImagePreview(reader.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleDeleteImage = () => {
    setImagePreview(null);
    setImageFile(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      // If there's a file upload, use FormData
      if (imageFile) {
        // Create FormData for file upload
        const data = new FormData();
        data.append('name', formData.name);
        data.append('job_title', formData.job_title);
        data.append('bio', formData.bio);
        data.append('profile_image', imageFile);
        
        console.log("Submitting with FormData:", Object.fromEntries(data.entries()));
        
        const success = await updateProfile(data);
        if (success) {
          setSuccess(true);
          setTimeout(() => setSuccess(false), 3000);
        }
      } else {
        // Regular JSON submission without file
        const dataToSubmit = {
          name: formData.name,
          job_title: formData.job_title,
          bio: formData.bio
        };
        
        console.log("Submitting JSON data:", dataToSubmit);
        
        const success = await updateProfile(dataToSubmit);
        if (success) {
          setSuccess(true);
          setTimeout(() => setSuccess(false), 3000);
        }
      }
    } catch (err) {
      console.error("Error submitting form:", err);
    }
  };

  return (
    <div className="settings-page">
      <Header />
      
      <div className="container">
        <div className="settings-container">
          <h1 className="settings-title">Profile settings</h1>
          
          <div className="settings-card">
            <form onSubmit={handleSubmit}>
              {error && <div className="error-message">{error}</div>}
              {success && <div className="success-message">Profile updated successfully!</div>}
              
              <div className="image-upload-section">
                <div className="image-container">
                  {imagePreview ? (
                    <img src={imagePreview} alt="Profile" className="profile-image" />
                  ) : (
                    <div className="profile-placeholder">
                      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                        <circle cx="12" cy="7" r="4"></circle>
                      </svg>
                    </div>
                  )}
                </div>
                
                <div className="image-info">
                  <p>Image must be 256 × 256px - max 2MB</p>
                  <div className="image-actions">
                    <label className="btn btn-secondary btn-sm">
                      Upload Profile Image
                      <input type="file" hidden accept="image/*" onChange={handleImageChange} />
                    </label>
                    
                    {imagePreview && (
                      <button type="button" className="btn btn-danger btn-sm" onClick={handleDeleteImage}>
                        Delete Image
                      </button>
                    )}
                  </div>
                </div>
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Email</label>
                  <input
                    type="email"
                    className="form-control"
                    placeholder="example@mail.com"
                    name="email"
                    value={formData.email}
                    disabled
                  />
                </div>
                
                <div className="form-group">
                  <label>Job title</label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="Enter your job title"
                    name="job_title"
                    value={formData.job_title}
                    onChange={handleChange}
                  />
                </div>
              </div>
              
              <div className="form-group">
                <label>Name</label>
                <input
                  type="text"
                  className="form-control"
                  placeholder="Enter your name"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                />
              </div>
              
              <div className="form-group">
                <label>Bio</label>
                <textarea
                  className="form-control"
                  placeholder="Enter a short introduction.."
                  name="bio"
                  value={formData.bio}
                  onChange={handleChange}
                  rows="5"
                ></textarea>
              </div>
              
              <div className="form-actions">
                <button type="submit" className="btn btn-primary" disabled={loading}>
                  {loading ? 'Saving...' : 'Save'}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfileSettings; 