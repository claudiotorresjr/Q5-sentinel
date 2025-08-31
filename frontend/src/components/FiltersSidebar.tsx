/**
 * Filters Sidebar Component
 * Advanced filtering interface with presets and real-time application
 */

import { useState } from 'react';
import { Search, X, Filter, RotateCcw, Save } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { Separator } from '@/components/ui/separator';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Checkbox } from '@/components/ui/checkbox';
import { useFiltersStore } from '@/stores/useFiltersStore';
import { Filters } from '@/types';

const FiltersSidebar = () => {
  const { filters, setFilter, resetFilters, applyPreset } = useFiltersStore();
  const [openSections, setOpenSections] = useState({
    exploration: true,
    confirmation: true,
    scale: false,
    domain: false,
    sla: true,
    management: true
  });

  const toggleSection = (section: keyof typeof openSections) => {
    setOpenSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const quickFilters = [
    { key: 'kev-only', label: 'Só KEV', active: filters.has_kev === true },
    { key: 'poc-available', label: 'Só PoC', active: filters.has_poc === true },
    { key: 'epss-high', label: 'EPSS ≥ 70%', active: filters.epss_score_min === 0.7 },
    { key: 'verified-only', label: 'Verified only', active: filters.is_verified === true },
    { key: 'dynamic-only', label: 'Dynamic only', active: filters.is_dynamic === true },
    { key: 'runtime-only', label: 'Runtime only', active: filters.is_runtime === true }
  ];

  const domains = [
    'web_api', 'backend_api', 'database', 'infrastructure', 
    'email_service', 'collaboration', 'search_index', 'file_transfer',
    'network_device', 'operating_system', 'web_server'
  ];

  const severities = ['critical', 'high', 'medium', 'low', 'none'];
  const environments = ['prod', 'dev', 'test'];
  const statuses = ['open', 'mitigated', 'accepted', 'false_positive'];

  return (
    <div className="w-80 h-full bg-card border-r border-border overflow-y-auto">
      <div className="sticky top-0 bg-card/95 backdrop-blur-sm z-10 p-4 border-b border-border">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Filter className="h-5 w-5" />
            Filtros
          </h2>
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="sm" onClick={resetFilters}>
              <RotateCcw className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm">
              <Save className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="CVE, componente, produto..."
            value={filters.search || ''}
            onChange={(e) => setFilter('search', e.target.value)}
            className="pl-10"
          />
          {filters.search && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setFilter('search', '')}
              className="absolute right-1 top-1 h-8 w-8 p-0"
            >
              <X className="h-4 w-4" />
            </Button>
          )}
        </div>

        {/* Quick Filters */}
        <div className="mt-4">
          <p className="text-sm font-medium mb-2">Filtros Rápidos</p>
          <div className="flex flex-wrap gap-1">
            {quickFilters.map((filter) => (
              <Badge
                key={filter.key}
                variant={filter.active ? "default" : "secondary"}
                className="cursor-pointer text-xs"
                onClick={() => applyPreset(filter.key)}
              >
                {filter.label}
              </Badge>
            ))}
          </div>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Exploration */}
        <Collapsible open={openSections.exploration} onOpenChange={() => toggleSection('exploration')}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="w-full justify-start p-0 h-auto">
              <h3 className="font-medium">Exploração</h3>
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-3 mt-3">
            <div className="flex items-center justify-between">
              <label className="text-sm">KEV (CISA)</label>
              <Switch
                checked={filters.has_kev === true}
                onCheckedChange={(checked) => setFilter('has_kev', checked ? true : undefined)}
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm">PoC Disponível</label>
              <Switch
                checked={filters.has_poc === true}
                onCheckedChange={(checked) => setFilter('has_poc', checked ? true : undefined)}
              />
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <label className="text-sm">EPSS Score ≥</label>
                <Badge variant="outline">
                  {filters.epss_score_min?.toFixed(2) || '0.00'}
                </Badge>
              </div>
              <Slider
                value={[filters.epss_score_min || 0]}
                onValueChange={([value]) => setFilter('epss_score_min', value > 0 ? value : undefined)}
                max={1}
                step={0.05}
              />
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <label className="text-sm">EPSS Percentile ≥</label>
                <Badge variant="outline">
                  {filters.epss_percentile_min || 0}%
                </Badge>
              </div>
              <Slider
                value={[filters.epss_percentile_min || 0]}
                onValueChange={([value]) => setFilter('epss_percentile_min', value > 0 ? value : undefined)}
                max={100}
                step={5}
              />
            </div>
          </CollapsibleContent>
        </Collapsible>

        <Separator />

        {/* RPI Score Filter */}
        <div className="space-y-3">
          <h3 className="font-medium">RPI Score</h3>
          <div className="space-y-3">
            {/* RPI Mínimo */}
            <div className="space-y-2">
              <div className="flex justify-between">
                <label className="text-sm">RPI Score ≥</label>
                <Badge variant="outline" className="bg-primary/10 text-primary font-mono">
                  {filters.rpi_min?.toFixed(1) || '0.0'}
                </Badge>
              </div>
              <Slider
                value={[filters.rpi_min || 0]}
                onValueChange={([value]) => setFilter('rpi_min', value > 0 ? value : undefined)}
                max={100}
                step={1}
                className="w-full"
              />
            </div>
            
            {/* RPI Máximo */}
            <div className="space-y-2">
              <div className="flex justify-between">
                <label className="text-sm">RPI Score ≤</label>
                <Badge variant="outline" className="bg-secondary/50 text-foreground font-mono">
                  {filters.rpi_max?.toFixed(1) || '100.0'}
                </Badge>
              </div>
              <Slider
                value={[filters.rpi_max || 100]}
                onValueChange={([value]) => setFilter('rpi_max', value < 100 ? value : undefined)}
                max={100}
                step={1}
                className="w-full"
              />
            </div>
            
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>0</span>
              <span className="text-yellow-600">Médio (40)</span>
              <span className="text-orange-600">Alto (60)</span>
              <span className="text-red-600">Crítico (80)</span>
              <span>100</span>
            </div>
          </div>
        </div>

        <Separator />

        {/* Confirmation */}
        <Collapsible open={openSections.confirmation} onOpenChange={() => toggleSection('confirmation')}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="w-full justify-start p-0 h-auto">
              <h3 className="font-medium">Confirmação</h3>
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-3 mt-3">
            <div className="flex items-center justify-between">
              <label className="text-sm">Verified only</label>
              <Switch
                checked={filters.is_verified === true}
                onCheckedChange={(checked) => setFilter('is_verified', checked ? true : undefined)}
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm">Dynamic only</label>
              <Switch
                checked={filters.is_dynamic === true}
                onCheckedChange={(checked) => setFilter('is_dynamic', checked ? true : undefined)}
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm">Runtime only</label>
              <Switch
                checked={filters.is_runtime === true}
                onCheckedChange={(checked) => setFilter('is_runtime', checked ? true : undefined)}
              />
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <label className="text-sm">Confidence ≥</label>
                <Badge variant="outline">
                  {filters.confidence_min?.toFixed(2) || '0.00'}
                </Badge>
              </div>
              <Slider
                value={[filters.confidence_min || 0]}
                onValueChange={([value]) => setFilter('confidence_min', value > 0 ? value : undefined)}
                max={1}
                step={0.05}
              />
            </div>
          </CollapsibleContent>
        </Collapsible>

        <Separator />

        {/* SLA */}
        <Collapsible open={openSections.sla} onOpenChange={() => toggleSection('sla')}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="w-full justify-start p-0 h-auto">
              <h3 className="font-medium">SLA</h3>
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-3 mt-3">
            <div className="flex items-center justify-between">
              <label className="text-sm">Só violados</label>
              <Switch
                checked={filters.sla_violated === true}
                onCheckedChange={(checked) => setFilter('sla_violated', checked ? true : undefined)}
              />
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <label className="text-sm">Dias restantes ≤</label>
                <Badge variant="outline">
                  {filters.sla_days_remaining_max || '∞'}
                </Badge>
              </div>
              <Slider
                value={[filters.sla_days_remaining_max || 30]}
                onValueChange={([value]) => setFilter('sla_days_remaining_max', value < 30 ? value : undefined)}
                max={30}
                step={1}
              />
            </div>
          </CollapsibleContent>
        </Collapsible>

        <Separator />

        {/* Management */}
        <Collapsible open={openSections.management} onOpenChange={() => toggleSection('management')}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="w-full justify-start p-0 h-auto">
              <h3 className="font-medium">Gestão</h3>
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-3 mt-3">
            <div className="flex items-center justify-between">
              <label className="text-sm">Ocultar resolvidas</label>
              <Switch
                checked={filters.hide_resolved === true}
                onCheckedChange={(checked) => setFilter('hide_resolved', checked)}
              />
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Status</label>
              {statuses.map((status) => (
                <div key={status} className="flex items-center space-x-2">
                  <Checkbox
                    id={status}
                    checked={filters.status?.includes(status) || false}
                    onCheckedChange={(checked) => {
                      const currentStatus = filters.status || [];
                      if (checked) {
                        setFilter('status', [...currentStatus, status]);
                      } else {
                        setFilter('status', currentStatus.filter(s => s !== status));
                      }
                    }}
                  />
                  <label htmlFor={status} className="text-sm capitalize">
                    {status.replace('_', ' ')}
                  </label>
                </div>
              ))}
            </div>
          </CollapsibleContent>
        </Collapsible>

        {/* Apply/Clear Buttons */}
        <div className="sticky bottom-0 bg-card/95 backdrop-blur-sm p-4 border-t border-border -mx-4 -mb-4">
          <div className="flex gap-2">
            <Button className="flex-1">Aplicar</Button>
            <Button variant="outline" className="flex-1" onClick={resetFilters}>
              Limpar
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FiltersSidebar;