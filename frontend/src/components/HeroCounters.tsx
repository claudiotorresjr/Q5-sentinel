/**
 * Hero Counters Component
 * Displays critical vulnerability metrics with pulsing animations
 */

import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { AlertTriangle, Shield, Bug, Target, TrendingUp } from 'lucide-react';
import { HeroCounterData } from '@/types';

interface HeroCountersProps {
  data: HeroCounterData;
}

const HeroCounters = ({ data }: HeroCountersProps) => {

  const counters = [
    {
      label: 'SLA Violado',
      value: data.sla_violated,
      icon: AlertTriangle,
      variant: 'critical' as const,
      pulse: data.sla_violated > 0,
      description: 'Vulnerabilidades com SLA vencido'
    },
    {
      label: 'SLA ≤ 7 dias',
      value: data.sla_warning,
      icon: Shield,
      variant: 'warning' as const,
      pulse: data.sla_warning > 0,
      description: 'Vulnerabilidades próximas do vencimento'
    },
    {
      label: 'KEV Ativo',
      value: data.kev_count,
      icon: Bug,
      variant: 'critical' as const,
      pulse: data.kev_count > 0,
      description: 'Exploração ativa confirmada (CISA KEV)'
    },
    {
      label: 'PoC Disponível',
      value: data.poc_count,
      icon: Target,
      variant: 'warning' as const,
      pulse: false,
      description: 'Proof of Concept público disponível'
    },
    {
      label: 'EPSS ≥ 90%',
      value: data.epss_high,
      icon: TrendingUp,
      variant: 'high' as const,
      pulse: false,
      description: 'Alto percentil EPSS (≥90)'
    }
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
      {counters.map((counter) => {
        const Icon = counter.icon;
        return (
          <Card key={counter.label} className="relative overflow-hidden">
            <CardContent className="p-4">
              <div className="flex items-start justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">{counter.label}</p>
                  <div className="flex items-center gap-2">
                    <span className="text-2xl font-bold tabular-nums">
                      {counter.value}
                    </span>
                    {counter.pulse && counter.value > 0 && (
                      <Badge 
                        variant={counter.variant}
                        className="animate-pulse-critical"
                      >
                        URGENTE
                      </Badge>
                    )}
                  </div>
                </div>
                <Icon 
                  className={`h-5 w-5 ${
                    counter.variant === 'critical' ? 'text-critical' :
                    counter.variant === 'warning' ? 'text-high' :
                    counter.variant === 'high' ? 'text-medium' :
                    'text-muted-foreground'
                  } ${counter.pulse && counter.value > 0 ? 'animate-pulse-critical' : ''}`}
                />
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                {counter.description}
              </p>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
};

export default HeroCounters;