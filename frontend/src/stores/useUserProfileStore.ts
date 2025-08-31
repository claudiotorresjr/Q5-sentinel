/**
 * Zustand store for managing user profile state
 * Handles user role selection for vulnerability explanations
 */

import { create } from 'zustand';

export type UserRole = 'analyst' | 'product_manager' | 'ceo';

interface UserProfileStore {
  userRole: UserRole;
  setUserRole: (role: UserRole) => void;
}

export const useUserProfileStore = create<UserProfileStore>((set) => ({
  userRole: 'analyst', // Default to analyst
  setUserRole: (role) => set({ userRole: role }),
}));
