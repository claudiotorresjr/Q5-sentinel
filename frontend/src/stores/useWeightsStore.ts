/**
 * Zustand store for managing RPI weight configuration
 * Handles weight adjustments and preset management
 */

import { create } from 'zustand';
import { WeightConfig } from '@/types';

interface WeightsStore {
  weights: WeightConfig;
  setWeight: (question: keyof WeightConfig, value: number | boolean) => void;
  applyPreset: (preset: string) => void;
  resetWeights: () => void;
  normalizeWeights: () => void;
}

const defaultWeights: WeightConfig = {
  q1_weight: 0.25,
  q2_weight: 0.20,
  q3_weight: 0.25,
  q4_weight: 0.15,
  q5_weight: 0.15,
  q1_enabled: true,
  q2_enabled: true,
  q3_enabled: true,
  q4_enabled: true,
  q5_enabled: true
};

export const useWeightsStore = create<WeightsStore>((set, get) => ({
  weights: defaultWeights,

  setWeight: (question, value) => {
    set((state) => ({
      weights: {
        ...state.weights,
        [question]: value
      }
    }));
  },

  applyPreset: (preset) => {
    const presets: Record<string, Partial<WeightConfig>> = {
      'sla-first': {
        q1_weight: 0.15,
        q2_weight: 0.15,
        q3_weight: 0.20,
        q4_weight: 0.15,
        q5_weight: 0.35
      },
      'exploit-first': {
        q1_weight: 0.40,
        q2_weight: 0.20,
        q3_weight: 0.20,
        q4_weight: 0.10,
        q5_weight: 0.10
      },
      'exposure-first': {
        q1_weight: 0.20,
        q2_weight: 0.35,
        q3_weight: 0.25,
        q4_weight: 0.10,
        q5_weight: 0.10
      },
      'impact-first': {
        q1_weight: 0.15,
        q2_weight: 0.15,
        q3_weight: 0.40,
        q4_weight: 0.15,
        q5_weight: 0.15
      },
      'balanced': {
        q1_weight: 0.20,
        q2_weight: 0.20,
        q3_weight: 0.20,
        q4_weight: 0.20,
        q5_weight: 0.20
      }
    };

    const presetWeights = presets[preset];
    if (presetWeights) {
      set((state) => ({
        weights: {
          ...state.weights,
          ...presetWeights
        }
      }));
    }
  },

  resetWeights: () => {
    set({ weights: defaultWeights });
  },

  normalizeWeights: () => {
    const state = get();
    const totalWeight = state.weights.q1_weight + state.weights.q2_weight + 
                       state.weights.q3_weight + state.weights.q4_weight + 
                       state.weights.q5_weight;
    
    if (totalWeight !== 1 && totalWeight > 0) {
      set((state) => ({
        weights: {
          ...state.weights,
          q1_weight: state.weights.q1_weight / totalWeight,
          q2_weight: state.weights.q2_weight / totalWeight,
          q3_weight: state.weights.q3_weight / totalWeight,
          q4_weight: state.weights.q4_weight / totalWeight,
          q5_weight: state.weights.q5_weight / totalWeight
        }
      }));
    }
  }
}));