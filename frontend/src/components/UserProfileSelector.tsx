/**
 * UserProfileSelector Component
 * Dropdown to select user role for vulnerability explanations
 */

import { useState } from 'react';
import { User, ChevronDown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { useUserProfileStore, UserRole } from '@/stores/useUserProfileStore';

const roleLabels: Record<UserRole, string> = {
  analyst: 'Analista',
  product_manager: 'Product Manager',
  ceo: 'CEO'
};

const roleDescriptions: Record<UserRole, string> = {
  analyst: 'Relatório técnico detalhado',
  product_manager: 'Foco em produto e roadmap',
  ceo: 'Resumo executivo de negócio'
};

const UserProfileSelector = () => {
  const { userRole, setUserRole } = useUserProfileStore();
  const [isOpen, setIsOpen] = useState(false);

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="hover:scale-105 transition-transform">
          <User className="h-4 w-4 mr-2" />
          {roleLabels[userRole]}
          <ChevronDown className="h-4 w-4 ml-2" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        {(Object.keys(roleLabels) as UserRole[]).map((role) => (
          <DropdownMenuItem
            key={role}
            onClick={() => {
              setUserRole(role);
              setIsOpen(false);
            }}
            className={userRole === role ? 'bg-accent' : ''}
          >
            <div className="flex flex-col">
              <span className="font-medium">{roleLabels[role]}</span>
              <span className="text-xs text-muted-foreground">{roleDescriptions[role]}</span>
            </div>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
};

export default UserProfileSelector;
