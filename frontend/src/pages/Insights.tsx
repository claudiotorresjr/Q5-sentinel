/**
 * Insights & Analytics Page  
 * Pareto analysis, domain breakdown, backlog hygiene, and tie analysis
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Target, BarChart3, Users, GitBranch } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Slider } from '@/components/ui/slider';
import { Badge } from '@/components/ui/badge';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const Insights = () => {
  const [paretoTarget, setParetoTarget] = useState([0.80]);
  
  // Mock data for visualizations
  const domainData = [
    { domain: 'web_api', count: 15, avgRpi: 78.2, color: '#ef4444' },
    { domain: 'backend_api', count: 8, avgRpi: 72.1, color: '#f97316' },
    { domain: 'database', count: 12, avgRpi: 68.4, color: '#eab308' },
    { domain: 'infrastructure', count: 6, avgRpi: 65.8, color: '#22c55e' },
    { domain: 'email_service', count: 4, avgRpi: 74.6, color: '#3b82f6' },
    { domain: 'collaboration', count: 3, avgRpi: 85.3, color: '#8b5cf6' }
  ];

  const statusData = [
    { status: 'open', count: 32, label: 'Aberto', color: '#ef4444' },
    { status: 'mitigated', count: 8, label: 'Mitigado', color: '#22c55e' },
    { status: 'accepted', count: 4, label: 'Aceito', color: '#eab308' },
    { status: 'false_positive', count: 2, label: 'Falso Positivo', color: '#6b7280' }
  ];

  const paretoData = [
    { rank: 1, coverage: 0.15, cumulative: 0.15 },
    { rank: 2, coverage: 0.12, cumulative: 0.27 },
    { rank: 3, coverage: 0.11, cumulative: 0.38 },
    { rank: 4, coverage: 0.09, cumulative: 0.47 },
    { rank: 5, coverage: 0.08, cumulative: 0.55 },
    { rank: 6, coverage: 0.07, cumulative: 0.62 },
    { rank: 7, coverage: 0.06, cumulative: 0.68 },
    { rank: 8, coverage: 0.05, cumulative: 0.73 },
    { rank: 9, coverage: 0.04, cumulative: 0.77 },
    { rank: 10, coverage: 0.04, cumulative: 0.81 },
    { rank: 11, coverage: 0.03, cumulative: 0.84 },
    { rank: 12, coverage: 0.03, cumulative: 0.87 }
  ];

  const tieGroups = [
    { size: 3, criteria: 'SLA>KEV>EPSSp>occ', topsisAvg: 0.89, bucket: 'Crítico' },
    { size: 4, criteria: 'KEV>PoC>EPSS>impact', topsisAvg: 0.82, bucket: 'Alto' },
    { size: 2, criteria: 'SLA>PoC>EPSSp>impact', topsisAvg: 0.76, bucket: 'Médio' },
    { size: 1, criteria: 'exposure>occ>PoC>impact', topsisAvg: 0.58, bucket: 'Baixo' }
  ];

  const targetK = Math.ceil(paretoData.find(d => d.cumulative >= paretoTarget[0])?.rank || 8);

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link to="/">
                <Button variant="ghost" size="sm">
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  Voltar
                </Button>
              </Link>
              <div>
                <h1 className="text-2xl font-bold">Insights & Analytics</h1>
                <p className="text-muted-foreground">Análise Pareto, distribuição por domínio e saúde do backlog</p>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        <div className="grid gap-6">
          {/* Pareto Analysis */}
          <div className="grid lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Target className="h-5 w-5" />
                    Análise de Pareto - Cobertura de Risco
                  </CardTitle>
                  <CardDescription>
                    Defina seu alvo de cobertura para ver quantas vulnerabilidades focar
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <label className="text-sm font-medium">Meta de Cobertura</label>
                      <Badge variant="outline">{(paretoTarget[0] * 100).toFixed(0)}%</Badge>
                    </div>
                    <Slider
                      value={paretoTarget}
                      onValueChange={setParetoTarget}
                      min={0.7}
                      max={0.95}
                      step={0.05}
                      className="w-full"
                    />
                  </div>
                  
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={paretoData.slice(0, 12)}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis 
                          dataKey="rank" 
                          stroke="#9ca3af"
                          tick={{ fontSize: 12 }}
                        />
                        <YAxis 
                          stroke="#9ca3af"
                          tick={{ fontSize: 12 }}
                          tickFormatter={(value) => `${(value * 100).toFixed(0)}%`}
                        />
                        <Tooltip 
                          formatter={(value: number) => [`${(value * 100).toFixed(1)}%`, 'Cobertura Cumulativa']}
                          labelFormatter={(label) => `Rank #${label}`}
                          contentStyle={{ 
                            backgroundColor: '#1f2937', 
                            border: '1px solid #374151',
                            borderRadius: '6px'
                          }}
                        />
                        <Bar 
                          dataKey="cumulative" 
                          fill="#ef4444"
                          radius={[2, 2, 0, 0]}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Recomendação Pareto</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="text-center space-y-2">
                  <div className="text-3xl font-bold text-primary">{targetK}</div>
                  <p className="text-sm text-muted-foreground">
                    vulnerabilidades necessárias para {(paretoTarget[0] * 100).toFixed(0)}% de cobertura
                  </p>
                </div>
                
                <Button className="w-full" variant="default">
                  <Target className="h-4 w-4 mr-2" />
                  Isolar Top-{targetK}
                </Button>

                <div className="pt-4 border-t border-border">
                  <p className="text-xs text-muted-foreground">
                    Baseado na distribuição atual de RPI scores e superfície de ataque
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Domain & Status Analysis */}
          <div className="grid lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BarChart3 className="h-5 w-5" />
                  Distribuição por Domínio
                </CardTitle>
                <CardDescription>RPI médio e contagem por domínio técnico</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={domainData} layout="horizontal">
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis 
                        type="number" 
                        stroke="#9ca3af"
                        tick={{ fontSize: 12 }}
                      />
                      <YAxis 
                        type="category" 
                        dataKey="domain" 
                        stroke="#9ca3af"
                        tick={{ fontSize: 12 }}
                        width={80}
                      />
                      <Tooltip 
                        formatter={(value: number, name: string) => {
                          if (name === 'avgRpi') return [`${value.toFixed(1)}`, 'RPI Médio'];
                          return [`${value}`, 'Contagem'];
                        }}
                        contentStyle={{ 
                          backgroundColor: '#1f2937', 
                          border: '1px solid #374151',
                          borderRadius: '6px'
                        }}
                      />
                      <Bar dataKey="avgRpi" fill="#ef4444" radius={[0, 2, 2, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  Saúde do Backlog
                </CardTitle>
                <CardDescription>Status das vulnerabilidades identificadas</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={statusData}
                          cx="50%"
                          cy="50%"
                          outerRadius={60}
                          dataKey="count"
                          stroke="none"
                        >
                          {statusData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip 
                          formatter={(value: number) => [`${value}`, 'Contagem']}
                          contentStyle={{ 
                            backgroundColor: '#1f2937', 
                            border: '1px solid #374151',
                            borderRadius: '6px'
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-2">
                    {statusData.map((item) => (
                      <div key={item.status} className="flex items-center gap-2">
                        <div 
                          className="w-3 h-3 rounded-full" 
                          style={{ backgroundColor: item.color }}
                        />
                        <span className="text-sm">{item.label}</span>
                        <Badge variant="outline" className="ml-auto">
                          {item.count}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Tie Analysis */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <GitBranch className="h-5 w-5" />
                Análise de Empates
              </CardTitle>
              <CardDescription>
                Grupos de vulnerabilidades com mesmo RPI e critérios de desempate
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4">
                {tieGroups.map((group, index) => (
                  <div key={index} className="flex items-center justify-between p-4 border border-border rounded-lg">
                    <div className="flex items-center gap-4">
                      <Badge variant="outline" className="tabular-nums">
                        {group.size} itens
                      </Badge>
                      <div>
                        <p className="font-medium">{group.criteria}</p>
                        <p className="text-sm text-muted-foreground">{group.bucket} Priority Bucket</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="font-medium">TOPSIS: {group.topsisAvg.toFixed(2)}</p>
                      <p className="text-xs text-muted-foreground">Confiança média</p>
                    </div>
                  </div>
                ))}
              </div>
              
              <div className="mt-6 p-4 bg-muted/50 rounded-lg">
                <p className="text-sm text-muted-foreground">
                  <strong>Critérios de desempate:</strong> SLA = SLA status, KEV = Known Exploited Vulnerability, 
                  PoC = Proof of Concept, EPSSp = EPSS Percentile, occ = Ocorrências, impact = Impacto CVSS
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Insights;