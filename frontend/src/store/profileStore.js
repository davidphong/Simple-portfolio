import { create } from 'zustand';
import { getProfile, updateProfile } from '../utils/api';

const useProfileStore = create((set) => ({
  profile: null,
  loading: false,
  error: null,
  
  fetchProfile: async () => {
    set({ loading: true, error: null });
    try {
      const response = await getProfile();
      set({ profile: response.data, loading: false });
      return response.data;
    } catch (error) {
      set({
        error: error.response?.data?.error || 'Failed to fetch profile',
        loading: false
      });
      return null;
    }
  },
  
  updateProfile: async (profileData) => {
    set({ loading: true, error: null });
    try {
      // Check if profileData is FormData (for file uploads) or regular object
      const isFormData = profileData instanceof FormData;
      
      // If it's not FormData, convert it to a regular JSON object
      const dataToSend = isFormData ? profileData : {
        name: profileData.name,
        job_title: profileData.job_title,
        bio: profileData.bio,
        profile_image: profileData.profile_image || null
      };
      
      const response = await updateProfile(dataToSend);
      
      // Update the store with the response data
      set({ 
        profile: response.data,
        loading: false 
      });
      return true;
    } catch (error) {
      console.error('Profile update error:', error);
      set({
        error: error.response?.data?.error || error.response?.data?.msg || 'Failed to update profile',
        loading: false
      });
      return false;
    }
  },
  
  clearError: () => {
    set({ error: null });
  }
}));

export default useProfileStore; 