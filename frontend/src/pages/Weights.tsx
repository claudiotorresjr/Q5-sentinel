/**
 * Weights Configuration Page
 * Panel for adjusting RPI 5Q weights and viewing impact on rankings
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, RotateCcw, Save, TrendingUp, TrendingDown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Slider } from '@/components/ui/slider';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

const Weights = () => {
  const [weights, setWeights] = useState({
    q1: 0.25,
    q2: 0.20,
    q3: 0.25,
    q4: 0.15,
    q5: 0.15
  });

  const [enabled, setEnabled] = useState({
    q1: true,
    q2: true,
    q3: true,
    q4: true,
    q5: true
  });

  // Mock ranking changes for top 20
  const rankingChanges = [
    { id: '1', cve: 'CVE-2021-44228', change: 0, product: 'Apache Log4j' },
    { id: '9', cve: 'CVE-2023-22515', change: 2, product: 'Atlassian Confluence' },
    { id: '2', cve: 'CVE-2019-0193', change: -1, product: 'Apache Solr' },
    { id: '12', cve: 'CVE-2023-20198', change: 1, product: 'Cisco IOS XE' },
    { id: '3', cve: 'CVE-2022-22965', change: 0, product: 'Spring Framework' }
  ];

  const presets = [
    { name: 'SLA-first', weights: { q1: 0.15, q2: 0.15, q3: 0.20, q4: 0.15, q5: 0.35 } },
    { name: 'Exploit-first', weights: { q1: 0.40, q2: 0.20, q3: 0.20, q4: 0.10, q5: 0.10 } },
    { name: 'Exposure-first', weights: { q1: 0.20, q2: 0.35, q3: 0.25, q4: 0.10, q5: 0.10 } },
    { name: 'Impact-first', weights: { q1: 0.15, q2: 0.15, q3: 0.40, q4: 0.15, q5: 0.15 } },
    { name: 'Balanced', weights: { q1: 0.20, q2: 0.20, q3: 0.20, q4: 0.20, q5: 0.20 } }
  ];

  const totalWeight = Object.values(weights).reduce((sum, w) => sum + w, 0);

  const applyPreset = (preset: typeof presets[0]) => {
    setWeights(preset.weights);
  };

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
                <h1 className="text-2xl font-bold">Configuração de Pesos</h1>
                <p className="text-muted-foreground">Ajuste os pesos das 5 perguntas do RPI</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm">
                <RotateCcw className="h-4 w-4 mr-2" />
                Reset
              </Button>
              <Button size="sm">
                <Save className="h-4 w-4 mr-2" />
                Salvar
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        <Tabs defaultValue="weights" className="space-y-6">
          <TabsList>
            <TabsTrigger value="weights">Pesos Básicos</TabsTrigger>
            <TabsTrigger value="advanced">MCDM Avançado</TabsTrigger>
          </TabsList>

          <TabsContent value="weights" className="space-y-6">
            <div className="grid lg:grid-cols-3 gap-6">
              {/* Weights Configuration */}
              <div className="lg:col-span-2 space-y-6">
                {/* Presets */}
                <Card>
                  <CardHeader>
                    <CardTitle>Presets Rápidos</CardTitle>
                    <CardDescription>
                      Configurações predefinidas para diferentes estratégias de priorização
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-2">
                      {presets.map((preset) => (
                        <Button
                          key={preset.name}
                          variant="outline"
                          size="sm"
                          onClick={() => applyPreset(preset)}
                        >
                          {preset.name}
                        </Button>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* Weight Sliders */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center justify-between">
                      Pesos das Perguntas
                      <Badge variant={totalWeight === 1 ? "default" : "destructive"}>
                        Soma: {totalWeight.toFixed(2)}
                      </Badge>
                    </CardTitle>
                    <CardDescription>
                      Ajuste a importância relativa de cada pergunta (soma deve ser 1.0)
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    {[
                      { key: 'q1', label: 'Q1 - Exploitabilidade', desc: 'KEV, PoC, EPSS score' },
                      { key: 'q2', label: 'Q2 - Exposição', desc: 'Superfície de ataque, ocorrências' },
                      { key: 'q3', label: 'Q3 - Impacto', desc: 'CVSS, criticidade do sistema' },
                      { key: 'q4', label: 'Q4 - Facilidade', desc: 'Esforço, disponibilidade de patch' },
                      { key: 'q5', label: 'Q5 - Urgência', desc: 'SLA, contexto temporal' }
                    ].map((q) => (
                      <div key={q.key} className="space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <Switch
                              checked={enabled[q.key as keyof typeof enabled]}
                              onCheckedChange={(checked) => 
                                setEnabled(prev => ({ ...prev, [q.key]: checked }))
                              }
                            />
                            <div>
                              <label className="text-sm font-medium">{q.label}</label>
                              <p className="text-xs text-muted-foreground">{q.desc}</p>
                            </div>
                          </div>
                          <Badge variant="outline">
                            {(weights[q.key as keyof typeof weights] * 100).toFixed(0)}%
                          </Badge>
                        </div>
                        <Slider
                          value={[weights[q.key as keyof typeof weights]]}
                          onValueChange={([value]) => 
                            setWeights(prev => ({ ...prev, [q.key]: value }))
                          }
                          max={1}
                          step={0.05}
                          className="w-full"
                          disabled={!enabled[q.key as keyof typeof enabled]}
                        />
                      </div>
                    ))}
                  </CardContent>
                </Card>
              </div>

              {/* Impact Preview */}
              <div className="space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle>Impacto no Ranking</CardTitle>
                    <CardDescription>
                      Mudanças no top-20 com os pesos atuais
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {rankingChanges.map((item, index) => (
                      <div key={item.id} className="flex items-center justify-between text-sm">
                        <div className="flex-1 min-w-0">
                          <p className="font-medium truncate">{item.cve}</p>
                          <p className="text-xs text-muted-foreground truncate">{item.product}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="tabular-nums">
                            #{index + 1}
                          </Badge>
                          {item.change !== 0 && (
                            <div className={`flex items-center gap-1 ${
                              item.change > 0 ? 'text-red-400' : 'text-green-400'
                            }`}>
                              {item.change > 0 ? (
                                <TrendingUp className="h-3 w-3" />
                              ) : (
                                <TrendingDown className="h-3 w-3" />
                              )}
                              <span className="text-xs">{Math.abs(item.change)}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="advanced" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>MCDM (TOPSIS) - Desempate Avançado</CardTitle>
                <CardDescription>
                  Configuração avançada para resolução de empates usando TOPSIS local
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="bg-muted/50 p-4 rounded-lg">
                  <p className="text-sm text-muted-foreground">
                    🚧 Esta funcionalidade está em desenvolvimento. O TOPSIS será usado para 
                    desempates quando múltiplas vulnerabilidades têm o mesmo RPI score, 
                    considerando critérios como EPSS percentile, número de ocorrências, 
                    confiança do scanner, e esforço de correção.
                  </p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default Weights;