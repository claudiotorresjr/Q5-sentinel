/**
 * RPI Score Cell Component
 * Displays RPI score with color-coded background
 */

import { Badge } from '@/components/ui/badge';

interface RpiCellProps {
  score: number;
  className?: string;
}

const RpiCell = ({ score, className = '' }: RpiCellProps) => {
  const getRpiVariant = (rpi: number) => {
    if (rpi >= 80) return 'critical';
    if (rpi >= 60) return 'high';
    if (rpi >= 40) return 'medium';
    return 'low';
  };

  const getRpiColor = (rpi: number) => {
    if (rpi >= 80) return 'bg-rpi-critical';
    if (rpi >= 60) return 'bg-rpi-high';
    if (rpi >= 40) return 'bg-rpi-medium';
    return 'bg-rpi-low';
  };

  return (
    <div className={`relative ${className}`}>
      <div className="flex items-center gap-2">
        <div className="relative w-16 h-6 bg-muted rounded-sm overflow-hidden">
          <div 
            className={`h-full transition-all duration-300 ${getRpiColor(score)}`}
            style={{ width: `${score}%` }}
          />
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-xs font-medium text-foreground mix-blend-difference">
              {score.toFixed(1)}
            </span>
          </div>
        </div>
        <Badge variant={getRpiVariant(score)} className="tabular-nums">
          {score.toFixed(0)}
        </Badge>
      </div>
    </div>
  );
};

export default RpiCell;