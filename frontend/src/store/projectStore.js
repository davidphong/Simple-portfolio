import { create } from 'zustand';
import { getProjects, addProject, updateProject, deleteProject } from '../utils/api';

const useProjectStore = create((set, get) => ({
  projects: [],
  loading: false,
  error: null,
  
  fetchProjects: async () => {
    set({ loading: true, error: null });
    try {
      const response = await getProjects();
      set({ projects: response.data, loading: false });
      return response.data;
    } catch (error) {
      set({
        error: error.response?.data?.error || 'Failed to fetch projects',
        loading: false
      });
      return [];
    }
  },
  
  addProject: async (projectData) => {
    set({ loading: true, error: null });
    try {
      const response = await addProject(projectData);
      const newProject = {
        id: response.data.id,
        name: response.data.name,
        demo_url: response.data.demo_url,
        repo_url: response.data.repo_url,
        description: response.data.description,
        image: response.data.image
      };
      
      set({ 
        projects: [...get().projects, newProject],
        loading: false 
      });
      return true;
    } catch (error) {
      set({
        error: error.response?.data?.error || 'Failed to add project',
        loading: false
      });
      return false;
    }
  },
  
  updateProject: async (projectId, projectData) => {
    set({ loading: true, error: null });
    try {
      const response = await updateProject(projectId, projectData);
      const updatedProject = response.data.project;
      
      set({ 
        projects: get().projects.map(p => 
          p.id === projectId ? updatedProject : p
        ),
        loading: false 
      });
      return true;
    } catch (error) {
      set({
        error: error.response?.data?.error || 'Failed to update project',
        loading: false
      });
      return false;
    }
  },
  
  deleteProject: async (projectId) => {
    set({ loading: true, error: null });
    try {
      await deleteProject(projectId);
      set({ 
        projects: get().projects.filter(p => p.id !== projectId),
        loading: false 
      });
      return true;
    } catch (error) {
      set({
        error: error.response?.data?.error || 'Failed to delete project',
        loading: false
      });
      return false;
    }
  },
  
  clearError: () => {
    set({ error: null });
  }
}));

export default useProjectStore; 