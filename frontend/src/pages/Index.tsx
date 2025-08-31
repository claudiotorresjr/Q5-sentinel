/**
 * VulnDesk Home Page - Priority Dashboard
 * Main vulnerability prioritization interface with filtering and triage
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Settings, Zap, BarChart3, Filter, Download, ChevronLeft, ChevronRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useFiltersStore } from '@/stores/useFiltersStore';
import { usePriorities, useHeroCounters } from '@/hooks/usePriorities';
import { useTestAPI } from '@/hooks/useTestAPI';
import HeroCounters from '@/components/HeroCounters';
import FiltersSidebar from '@/components/FiltersSidebar';
import VulnerabilityCard from '@/components/VulnerabilityCard';
import { ThemeToggle } from '@/components/ThemeToggle';
import UserProfileSelector from '@/components/UserProfileSelector';

const Index = () => {
  const { filters, isTriageMode, toggleTriageMode } = useFiltersStore();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const checkTheme = () => {
      const savedTheme = localStorage.getItem('theme');
      const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      const isCurrentlyDark = savedTheme === 'dark' || (!savedTheme && systemDark) || document.documentElement.classList.contains('dark');
      setIsDark(isCurrentlyDark);
    };

    checkTheme();

    // Listen for theme changes
    const observer = new MutationObserver(checkTheme);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

    return () => observer.disconnect();
  }, []);

  const logoSrc = isDark ? "/image.png" : "/image_white.png";

  // Fetch prioritized vulnerabilities with pagination
  const { data: response, isLoading, error } = usePriorities({ ...filters, page: currentPage });
  const vulnerabilities = response?.data || [];
  const pagination = response?.pagination;

  // Fetch hero counter data from backend
  const { data: heroData, isLoading: heroLoading } = useHeroCounters();

  // Test API connection
  const { data: testData, error: testError } = useTestAPI();

  if (error) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-destructive mb-2">Erro ao carregar dados</h1>
          <p className="text-muted-foreground">Não foi possível carregar as vulnerabilidades.</p>
          <p className="text-sm text-muted-foreground mt-4">Error: {error.message}</p>
          <p className="text-sm text-muted-foreground">Test API: {testData ? JSON.stringify(testData) : 'Not loaded'}</p>
          <p className="text-sm text-muted-foreground">Test Error: {testError ? testError.message : 'None'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Top Navigation */}
      <header className="border-b border-border bg-gradient-to-r from-card/80 to-card/60 backdrop-blur-md sticky top-0 z-50 shadow-sm">
        <div className="container mx-auto px-6 py-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              {/* Logo and Brand */}
              <Link to="/" className="flex items-center gap-4 hover:opacity-80 transition-opacity">
                <img
                  src={logoSrc}
                  alt="Q5 Sentinel Logo"
                  className="h-24 w-24 drop-shadow-sm"
                />
                <div>
                  <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-primary/80 bg-clip-text text-transparent">
                    Q5 Sentinel
                  </h1>
                  <p className="text-sm text-muted-foreground font-medium">
                    Priorização RPI 5Q • {pagination?.total || 0} vulnerabilidades
                  </p>
                </div>
              </Link>

            </div>

            {/* Action Buttons */}
            <div className="flex items-center gap-2">
              <Button
                variant={isTriageMode ? "default" : "outline"}
                size="sm"
                onClick={toggleTriageMode}
                className="hover:scale-105 transition-transform"
              >
                <Zap className="h-4 w-4 mr-2" />
                {isTriageMode ? 'Sair Triagem' : 'Modo Triagem'}
              </Button>

              <Button variant="outline" size="sm" className="hover:scale-105 transition-transform">
                <Filter className="h-4 w-4 mr-2" />
                Filtros
              </Button>

              <Button variant="outline" size="sm" className="hover:scale-105 transition-transform">
                <Download className="h-4 w-4 mr-2" />
                Exportar
              </Button>

              <Link to="/weights">
                <Button variant="outline" size="sm" className="hover:scale-105 transition-transform">
                  <Settings className="h-4 w-4 mr-2" />
                  Pesos
                </Button>
              </Link>

              <Link to="/insights">
                <Button variant="outline" size="sm" className="hover:scale-105 transition-transform">
                  <BarChart3 className="h-4 w-4 mr-2" />
                  Insights
                </Button>
              </Link>

              <UserProfileSelector />

              <ThemeToggle />
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Filters Sidebar */}
        {sidebarOpen && <FiltersSidebar />}

        {/* Main Content */}
        <div className="flex-1 p-6">
          <div className="max-w-7xl mx-auto space-y-6">
            {/* Total Count Card */}
            <div className="bg-card border border-border rounded-lg p-6 text-center">
              <h3 className="text-4xl font-bold text-primary mb-2">
                {pagination?.total || vulnerabilities.length}
              </h3>
              <p className="text-muted-foreground font-medium">
                Vulnerabilidades Total
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                Sistema Q5 Sentinel
              </p>
            </div>

            {/* Hero Counters */}
            <HeroCounters
              data={heroData || { sla_violated: 0, sla_warning: 0, kev_count: 0, poc_count: 0, epss_high: 0, total_count: 0 }}
            />

            {/* Vulnerability Cards */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">
                  Vulnerabilidades Priorizadas
                </h2>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">
                    {pagination ? `${vulnerabilities.length} de ${pagination.total}` : `${vulnerabilities.length} vulnerabilidades`}
                  </Badge>
                  {isLoading && (
                    <Badge variant="outline" className="animate-pulse">
                      Carregando...
                    </Badge>
                  )}
                </div>
              </div>

              {/* Cards Content */}
              {isLoading ? (
                <div className="flex items-center justify-center p-12">
                  <div className="text-center">
                    <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full mx-auto mb-4" />
                    <p className="text-muted-foreground">Carregando vulnerabilidades...</p>
                  </div>
                </div>
              ) : vulnerabilities.length === 0 ? (
                <div className="flex items-center justify-center p-12">
                  <p className="text-muted-foreground">Nenhuma vulnerabilidade encontrada com os filtros atuais.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {vulnerabilities.map((vuln, index) => (
                    <VulnerabilityCard
                      key={vuln.id}
                      vulnerability={vuln}
                      rank={((currentPage - 1) * 100) + index + 1}
                    />
                  ))}

                  {/* Pagination Controls */}
                  {pagination && pagination.total_pages > 1 && (
                    <div className="flex items-center justify-between py-6">
                      <div className="text-sm text-muted-foreground">
                        Página {pagination.page} de {pagination.total_pages} • {pagination.total} vulnerabilidades total
                      </div>

                      <div className="flex items-center gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setCurrentPage(currentPage - 1)}
                          disabled={!pagination.has_prev}
                        >
                          <ChevronLeft className="h-4 w-4 mr-1" />
                          Anterior
                        </Button>

                        <div className="flex items-center gap-1">
                          {Array.from({ length: Math.min(5, pagination.total_pages) }, (_, i) => {
                            const page = i + 1;
                            return (
                              <Button
                                key={page}
                                variant={page === currentPage ? "default" : "outline"}
                                size="sm"
                                onClick={() => setCurrentPage(page)}
                                className="w-8 h-8 p-0"
                              >
                                {page}
                              </Button>
                            );
                          })}
                        </div>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setCurrentPage(currentPage + 1)}
                          disabled={!pagination.has_next}
                        >
                          Próxima
                          <ChevronRight className="h-4 w-4 ml-1" />
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
