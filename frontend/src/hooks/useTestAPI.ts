import { useQuery } from '@tanstack/react-query';

export const useTestAPI = () => {
  return useQuery({
    queryKey: ['test'],
    queryFn: async () => {
      const response = await fetch('http://localhost:5050/test');
      if (!response.ok) {
        throw new Error('Failed to fetch test');
      }
      return response.json();
    },
    refetchOnWindowFocus: false
  });
};
