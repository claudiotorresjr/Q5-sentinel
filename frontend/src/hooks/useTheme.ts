import { useEffect, useState } from 'react';

type Theme = 'light' | 'dark';

export const useTheme = () => {
  const [theme, setTheme] = useState<Theme>('light');

  useEffect(() => {
    // Check if there's a saved theme in localStorage
    const savedTheme = localStorage.getItem('theme') as Theme;
    console.log('Initializing theme - saved theme:', savedTheme);
    if (savedTheme && (savedTheme === 'light' || savedTheme === 'dark')) {
      console.log('Using saved theme:', savedTheme);
      setTheme(savedTheme);
    } else {
      // Default to light theme
      console.log('No saved theme found, defaulting to light');
      setTheme('light');
    }
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    
    console.log('Applying theme:', theme);
    if (theme === 'dark') {
      root.classList.add('dark');
      console.log('Added dark class to html element');
    } else {
      root.classList.remove('dark');
      console.log('Removed dark class from html element');
    }
    
    // Save theme preference
    localStorage.setItem('theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    console.log('Toggling theme from', theme, 'to', newTheme);
    setTheme(newTheme);
  };

  return { theme, toggleTheme };
};