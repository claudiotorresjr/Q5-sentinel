/**
 * Custom hook for fetching and managing vulnerability priorities
 * Simulates API calls with mock data and filtering
 */

import { useQuery } from '@tanstack/react-query';
import { Vuln, Filters, HeroCounterData } from '@/types';

/**
 * Simulates network latency for realistic UX testing
 */
const simulateLatency = (ms: number = 500) => 
  new Promise(resolve => setTimeout(resolve, ms));

/**
 * API call to fetch priorities with filters and pagination from real backend
 */
const fetchPriorities = async (filters: Filters & { page?: number }): Promise<{data: Vuln[], pagination: any}> => {
  // Build query parameters
  const params = new URLSearchParams();
  
  if (filters.search) params.append('search', filters.search);
  if (filters.has_kev !== undefined) params.append('has_kev', filters.has_kev.toString());
  if (filters.has_poc !== undefined) params.append('has_poc', filters.has_poc.toString());
  if (filters.domains && filters.domains.length === 1) params.append('domain', filters.domains[0]);
  if (filters.severities && filters.severities.length === 1) params.append('severity', filters.severities[0]);
  if (filters.rpi_min !== undefined) params.append('rpi_min', filters.rpi_min.toString());
  if (filters.rpi_max !== undefined) params.append('rpi_max', filters.rpi_max.toString());
  
  // Pagination
  params.append('page', (filters.page || 1).toString());
  params.append('limit', '100');
  
  const apiUrl = `http://localhost:5000/api/priorities?${params.toString()}`;
  
  console.log('Fetching from:', apiUrl);
  
  try {
    const response = await fetch(apiUrl);
    console.log('Response status:', response.status);
    if (!response.ok) {
      throw new Error(`Failed to fetch priorities from API: ${response.status} ${response.statusText}`);
    }
    const result = await response.json();
    return result;
  } catch (error) {
    console.error('Fetch error:', error);
    throw error;
  }
};

/**
 * Calculate hero counter metrics from vulnerability data
 */
const calculateHeroCounters = (vulns: Vuln[]): HeroCounterData => {
  return {
    sla_violated: vulns.filter(v => v.violates_sla).length,
    sla_warning: vulns.filter(v => !v.violates_sla && v.sla_days_remaining !== undefined && v.sla_days_remaining <= 7).length,
    kev_count: vulns.filter(v => v.has_kev).length,
    poc_count: vulns.filter(v => v.has_poc).length,
    epss_high: vulns.filter(v => v.epss_percentile !== undefined && v.epss_percentile >= 90).length,
    total_count: vulns.length
  };
};

/**
 * Hook for fetching prioritized vulnerabilities with pagination
 */
export const usePriorities = (filters: Filters & { page?: number }) => {
  return useQuery({
    queryKey: ['priorities', filters],
    queryFn: () => fetchPriorities(filters),
    staleTime: 5 * 60 * 1000, // 5 minutes
    refetchOnWindowFocus: false
  });
};

/**
 * Fetch hero counters from backend
 */
const fetchHeroCounters = async (): Promise<HeroCounterData> => {
  console.log('Fetching hero counters...');
  try {
    const response = await fetch('http://localhost:5000/api/hero-counters');
    console.log('Hero counters response status:', response.status);
    if (!response.ok) {
      throw new Error(`Failed to fetch hero counters: ${response.status} ${response.statusText}`);
    }
    const data = await response.json();
    console.log('Hero counters data:', data);
    return data;
  } catch (error) {
    console.error('Hero counters error:', error);
    throw error;
  }
};

/**
 * Hook for fetching hero counter data from backend
 */
export const useHeroCounters = () => {
  return useQuery({
    queryKey: ['hero-counters'],
    queryFn: fetchHeroCounters,
    staleTime: 2 * 60 * 1000, // 2 minutes
    refetchOnWindowFocus: false
  });
};

/**
 * Hook for calculating hero counter data from local data (fallback)
 */
export const useLocalHeroCounters = (vulns: Vuln[] = []) => {
  return calculateHeroCounters(vulns);
};