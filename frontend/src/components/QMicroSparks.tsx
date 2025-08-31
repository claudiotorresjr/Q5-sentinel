/**
 * Q1-Q5 Micro Sparks Component
 * Displays mini bar charts for the 5Q methodology scores
 * Enhanced with security-focused colors and detailed tooltips
 */

import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from '@/components/ui/tooltip';

interface QMicroSparksProps {
  q1_exploitability?: number;
  q2_exposure?: number;
  q3_impact?: number;
  q4_fixability?: number;
  q5_urgency?: number;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const QMicroSparks = ({ 
  q1_exploitability, 
  q2_exposure, 
  q3_impact, 
  q4_fixability, 
  q5_urgency,
  size = 'md',
  className = '' 
}: QMicroSparksProps) => {
  const questions = [
    { 
      key: 'Q1', 
      value: q1_exploitability, 
      label: 'Exploitabilidade', 
      color: 'bg-critical',
      description: 'Facilidade de exploração da vulnerabilidade',
      detail: 'Avalia a complexidade técnica, pré-requisitos de acesso e disponibilidade de exploits'
    },
    { 
      key: 'Q2', 
      value: q2_exposure, 
      label: 'Exposição', 
      color: 'bg-high',
      description: 'Grau de exposição do ativo vulnerável',
      detail: 'Considera visibilidade externa, criticidade do sistema e arquitetura de rede'
    },
    { 
      key: 'Q3', 
      value: q3_impact, 
      label: 'Impacto', 
      color: 'bg-medium',
      description: 'Consequências potenciais da exploração',
      detail: 'Avalia impacto nos pilares CIA (Confidencialidade, Integridade, Disponibilidade)'
    },
    { 
      key: 'Q4', 
      value: q4_fixability, 
      label: 'Remediabilidade', 
      color: 'bg-blue-500',
      description: 'Facilidade de correção (maior = mais fácil)',
      detail: 'Considera disponibilidade de patches, complexidade de deploy e impacto operacional'
    },
    { 
      key: 'Q5', 
      value: q5_urgency, 
      label: 'Urgência', 
      color: 'bg-purple-500',
      description: 'Urgência contextual de correção',
      detail: 'Fatores temporais: KEV, PoC público, exploração ativa, SLA e contexto de negócio'
    }
  ];

  const getSizeClasses = () => {
    switch (size) {
      case 'sm':
        return {
          container: 'gap-0.5',
          bar: 'w-2 h-6 rounded-sm',
          text: 'text-[10px]'
        };
      case 'lg':
        return {
          container: 'gap-1.5',
          bar: 'w-4 h-12 rounded-md',
          text: 'text-xs'
        };
      default:
        return {
          container: 'gap-1',
          bar: 'w-3 h-8 rounded-sm',
          text: 'text-xs'
        };
    }
  };

  const sizeClasses = getSizeClasses();

  return (
    <TooltipProvider>
      <div className={`flex items-end ${sizeClasses.container} ${className}`}>
        {questions.map((q) => {
          const normalizedValue = Math.max(0, Math.min(100, q.value || 0));
          
          return (
            <Tooltip key={q.key}>
              <TooltipTrigger asChild>
                <div className="flex flex-col items-center gap-1 cursor-pointer">
                  <div className={`${sizeClasses.bar} bg-muted/30 rounded-sm overflow-hidden relative group`}>
                    <div 
                      className={`w-full ${q.color} transition-all duration-500 ease-out group-hover:brightness-110 absolute bottom-0`}
                      style={{ 
                        height: `${normalizedValue}%`,
                      }}
                    />
                    {/* Subtle glow effect on hover */}
                    <div 
                      className={`absolute inset-0 ${q.color} opacity-0 group-hover:opacity-20 transition-opacity duration-300 blur-sm`}
                      style={{ 
                        height: `${normalizedValue}%`,
                        marginTop: `${100 - normalizedValue}%`
                      }}
                    />
                  </div>
                  <span className={`${sizeClasses.text} text-muted-foreground font-medium transition-colors group-hover:text-foreground`}>
                    {q.key}
                  </span>
                </div>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs">
                <div className="text-left space-y-2">
                  <div className="font-semibold text-sm text-primary">
                    {q.key}: {q.label}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {q.description}
                  </div>
                  <div className="text-xs text-muted-foreground/80">
                    {q.detail}
                  </div>
                  <div className="pt-1 border-t border-border">
                    <span className="text-sm font-bold text-foreground">
                      Score: {q.value?.toFixed(1) || 'N/A'}
                    </span>
                  </div>
                </div>
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
};

export default QMicroSparks;