import React, { useState, useEffect } from 'react';
import useProjectStore from '../store/projectStore';
import useAuthStore from '../store/authStore';
import Header from '../components/Header';
import './Settings.css';

const ProjectsSettings = () => {
  const { projects, fetchProjects, addProject, updateProject, deleteProject, loading, error } = useProjectStore();
  const { isAuthenticated } = useAuthStore();
  const [showModal, setShowModal] = useState(false);
  const [currentProject, setCurrentProject] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    demo_url: '',
    repo_url: '',
    description: ''
  });
  const [imagePreview, setImagePreview] = useState(null);
  const [imageFile, setImageFile] = useState(null);
  const [success, setSuccess] = useState(false);
  
  useEffect(() => {
    if (isAuthenticated()) {
      fetchProjects();
    }
  }, [fetchProjects, isAuthenticated]);

  const openAddModal = () => {
    setCurrentProject(null);
    setFormData({
      name: '',
      demo_url: '',
      repo_url: '',
      description: ''
    });
    setImagePreview(null);
    setImageFile(null);
    setShowModal(true);
  };

  const openEditModal = (project) => {
    setCurrentProject(project);
    setFormData({
      name: project.name || '',
      demo_url: project.demo_url || '',
      repo_url: project.repo_url || '',
      description: project.description || ''
    });
    
    if (project.image) {
      setImagePreview(`${process.env.REACT_APP_API_URL || 'http://localhost:7331'}/uploads/${project.image}`);
    } else {
      setImagePreview(null);
    }
    
    setImageFile(null);
    setShowModal(true);
  };

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
    
    // Create FormData for file upload
    const data = new FormData();
    data.append('name', formData.name);
    data.append('demo_url', formData.demo_url);
    data.append('repo_url', formData.repo_url);
    data.append('description', formData.description);
    
    if (imageFile) {
      data.append('image', imageFile);
    }
    
    let success = false;
    
    if (currentProject) {
      success = await updateProject(currentProject.id, data);
    } else {
      success = await addProject(data);
    }
    
    if (success) {
      setShowModal(false);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    }
  };

  const handleDelete = async (projectId) => {
    if (window.confirm('Are you sure you want to delete this project?')) {
      const success = await deleteProject(projectId);
      if (success) {
        setSuccess(true);
        setTimeout(() => setSuccess(false), 3000);
      }
    }
  };

  return (
    <div className="settings-page">
      <Header />
      
      <div className="container">
        <div className="settings-container">
          <h1 className="settings-title">Projects settings</h1>
          
          <div className="add-project-container">
            <button className="add-project-btn" onClick={openAddModal}>
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M10 4V16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M4 10H16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <span>Add project</span>
            </button>
          </div>
          
          {error && <div className="error-message">{error}</div>}
          {success && <div className="success-message">Changes saved successfully!</div>}
          
          <div className="projects-grid">
            {projects.map(project => (
              <div className="project-card" key={project.id}>
                <div className="project-image">
                  {project.image ? (
                    <img 
                      src={`${process.env.REACT_APP_API_URL || 'http://localhost:7331'}/uploads/${project.image}`} 
                      alt={project.name} 
                    />
                  ) : (
                    <span>No Image</span>
                  )}
                </div>
                <div className="project-info">
                  <h3 className="project-title">{project.name}</h3>
                  <p className="project-description">{project.description}</p>
                </div>
                <div className="project-actions">
                  <button 
                    className="btn btn-primary" 
                    onClick={() => openEditModal(project)}
                  >
                    Edit
                  </button>
                  <button 
                    className="btn btn-danger" 
                    onClick={() => handleDelete(project.id)}
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
          
          {/* Project Modal */}
          {showModal && (
            <div className="modal-backdrop">
              <div className="modal">
                <div className="modal-header">
                  <h2 className="modal-title">{currentProject ? 'Edit Project' : 'Add Project'}</h2>
                  <button 
                    className="modal-close" 
                    onClick={() => setShowModal(false)}
                  >
                    &times;
                  </button>
                </div>
                <div className="modal-body">
                  <form onSubmit={handleSubmit}>
                    <div className="image-upload-section">
                      <div className="image-container">
                        {imagePreview ? (
                          <img src={imagePreview} alt="Project" className="profile-image" />
                        ) : (
                          <div className="profile-placeholder">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
                              <circle cx="8.5" cy="8.5" r="1.5"></circle>
                              <polyline points="21 15 16 10 5 21"></polyline>
                            </svg>
                          </div>
                        )}
                      </div>
                      
                      <div className="image-info">
                        <p>Image must be PNG or JPEG - max 2MB</p>
                        <div className="image-actions">
                          <label className="btn btn-secondary btn-sm">
                            Upload Image
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
                    
                    <div className="form-group">
                      <label>Project Name</label>
                      <input
                        type="text"
                        className="form-control"
                        placeholder="Enter your project name"
                        name="name"
                        value={formData.name}
                        onChange={handleChange}
                        required
                      />
                    </div>
                    
                    <div className="form-group">
                      <label>Demo URL</label>
                      <input
                        type="url"
                        className="form-control"
                        placeholder="Enter the demo URL"
                        name="demo_url"
                        value={formData.demo_url}
                        onChange={handleChange}
                      />
                    </div>
                    
                    <div className="form-group">
                      <label>Repository URL</label>
                      <input
                        type="url"
                        className="form-control"
                        placeholder="Enter the repository URL"
                        name="repo_url"
                        value={formData.repo_url}
                        onChange={handleChange}
                      />
                    </div>
                    
                    <div className="form-group">
                      <label>Description</label>
                      <textarea
                        className="form-control"
                        placeholder="Enter a short description.."
                        name="description"
                        value={formData.description}
                        onChange={handleChange}
                        rows="3"
                      ></textarea>
                    </div>
                    
                    <div className="modal-footer">
                      <button 
                        type="button" 
                        className="btn btn-secondary" 
                        onClick={() => setShowModal(false)}
                      >
                        Cancel
                      </button>
                      <button 
                        type="submit" 
                        className="btn btn-primary" 
                        disabled={loading}
                      >
                        {loading ? 'Saving...' : 'Add'}
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ProjectsSettings; 