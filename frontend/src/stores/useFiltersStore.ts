/**
 * Zustand store for managing filter state
 * Handles all filtering logic and URL synchronization
 */

import { create } from 'zustand';
import { Filters } from '@/types';

interface FiltersStore {
  filters: Filters;
  isTriageMode: boolean;
  selectedIds: string[];
  setFilter: <K extends keyof Filters>(key: K, value: Filters[K]) => void;
  resetFilters: () => void;
  toggleTriageMode: () => void;
  toggleSelection: (id: string) => void;
  selectAll: (ids: string[]) => void;
  clearSelection: () => void;
  applyPreset: (preset: string) => void;
}

const defaultFilters: Filters = {
  search: '',
  has_kev: undefined,
  has_poc: undefined,
  epss_score_min: undefined,
  epss_percentile_min: undefined,
  is_verified: undefined,
  is_dynamic: undefined,
  is_static: undefined,
  confidence_min: undefined,
  nb_occurences_min: undefined,
  nb_endpoints_min: undefined,
  domains: [],
  severities: [],
  environments: [],
  rpi_min: undefined,
  rpi_max: undefined,
  q4_min: undefined,
  effort_max: undefined,
  sla_violated: undefined,
  sla_days_remaining_max: undefined,
  hide_resolved: true, // Default to hiding resolved items
  status: ['open'] // Default to only showing open items
};

export const useFiltersStore = create<FiltersStore>((set, get) => ({
  filters: defaultFilters,
  isTriageMode: false,
  selectedIds: [],

  setFilter: (key, value) => {
    set((state) => ({
      filters: {
        ...state.filters,
        [key]: value
      }
    }));
  },

  resetFilters: () => {
    set({
      filters: defaultFilters,
      selectedIds: []
    });
  },

  toggleTriageMode: () => {
    set((state) => ({
      isTriageMode: !state.isTriageMode,
      selectedIds: [] // Clear selection when toggling mode
    }));
  },

  toggleSelection: (id) => {
    set((state) => ({
      selectedIds: state.selectedIds.includes(id)
        ? state.selectedIds.filter(selectedId => selectedId !== id)
        : [...state.selectedIds, id]
    }));
  },

  selectAll: (ids) => {
    set({ selectedIds: ids });
  },

  clearSelection: () => {
    set({ selectedIds: [] });
  },

  applyPreset: (preset) => {
    const presets: Record<string, Partial<Filters>> = {
      'kev-only': {
        has_kev: true
      },
      'poc-available': {
        has_poc: true
      },
      'epss-high': {
        epss_score_min: 0.7,
        epss_percentile_min: 90
      },
      'sla-critical': {
        sla_violated: true,
        sla_days_remaining_max: 7
      },
      'verified-only': {
        is_verified: true
      },
      'dynamic-only': {
        is_dynamic: true
      },
      'runtime-only': {
        is_runtime: true
      },
      'rpi-critical': {
        rpi_min: 80
      },
      'rpi-high': {
        rpi_min: 60
      }
    };

    const presetFilters = presets[preset];
    if (presetFilters) {
      set((state) => ({
        filters: {
          ...state.filters,
          ...presetFilters
        }
      }));
    }
  }
}));