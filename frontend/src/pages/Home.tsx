/**
 * Q5 Sentinel Home Page
 * Landing page de alto impacto para produto de priorização de vulnerabilidades
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Zap,
  Target,
  Clock,
  CheckCircle,
  ArrowRight,
  BarChart3,
  Filter,
  Eye,
  AlertTriangle,
  TrendingUp,
  Play,
  Calendar,
  Users,
  Star,
  Quote
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ThemeToggle } from '@/components/ThemeToggle';

const Home = () => {
  const [hoveredQ, setHoveredQ] = useState<number | null>(null);
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

  const qQuestions = [
    {
      id: 1,
      title: "Q1 — Exploitability",
      subtitle: "Quão explorável é?",
      description: "Combina KEV, PoC real, EPSS (score + percentile), sinais de vetor (rede/adjacente/local), requisitos de privilégios e interação, além de heurísticas por CWE.",
      color: "text-red-500",
      bgColor: "bg-red-500/10 hover:bg-red-500/20"
    },
    {
      id: 2,
      title: "Q2 — Exposição",
      subtitle: "Está de fato exposta e alcançável?",
      description: "Favorece evidência dinâmica (runtime), URLs/Endpoints, produção vs dev/test, dependência de runtime vs dev, e domínio do componente.",
      color: "text-orange-500",
      bgColor: "bg-orange-500/10 hover:bg-orange-500/20"
    },
    {
      id: 3,
      title: "Q3 — Impacto",
      subtitle: "Se der ruim, qual o estrago?",
      description: "Usa CVSS v3.1 (vetor C/I/A e escopo), criticidade do ativo, ocorrências/endpoints (blast radius), sensibilidade de dados e perfil CIA por CWE.",
      color: "text-amber-500",
      bgColor: "bg-amber-500/10 hover:bg-amber-500/20"
    },
    {
      id: 4,
      title: "Q4 — Fixabilidade",
      subtitle: "Quanto esforço para corrigir?",
      description: "Considera disponibilidade de patch/upgrade, abrangência da mudança, janela de manutenção, riscos de regressão e velocidade de rollback.",
      color: "text-blue-500",
      bgColor: "bg-blue-500/10 hover:bg-blue-500/20"
    },
    {
      id: 5,
      title: "Q5 — Urgência",
      subtitle: "Quanto tempo eu tenho antes de doer?",
      description: "Junta SLA (crítico), ameaça contínua (EPSS/PoC/KEV), idade com gating, exposição Q2 e reforços de Q1/Q3. Derruba falsos positivos.",
      color: "text-purple-500",
      bgColor: "bg-purple-500/10 hover:bg-purple-500/20"
    }
  ];

  const benefits = [
    {
      icon: Target,
      title: "Priorizações que fazem sentido",
      description: "Top-K com Pareto 80/20: quantos itens cobrem 80–90% do risco? Explicabilidade waterfall 5Q por item."
    },
    {
      icon: Filter,
      title: "Falso positivo lá embaixo",
      description: "Age-gating + Q1/Q2/Q3 derrubam casos frios e internos. Confiança do scanner pesa no final."
    },
    {
      icon: Zap,
      title: "Fluxo que economiza horas",
      description: "Filtros rápidos (KEV, PoC, EPSS≥X), Modo Triagem (j/k/a/m/x), seleção em lote e export."
    }
  ];

  const integrations = [
    "KEV (CISA)", "EPSS (FIRST)", "NVD", "CVE.org", "OSV", "Exploit-DB", "Metasploit"
  ];

  const features = [
    "Pareto Interativo — deslize o alvo (70–95%) e veja o K exato",
    "Presets & Pesos Dinâmicos — troque o viés sem perder contexto",
    "Filtros de um clique — KEV, PoC, EPSS ≥ X, Prod/Dev",
    "Microssparks 5Q — entenda cada Q em segundos",
    "Why-This-Rank — transparência completa de desempates",
    "Modo Triagem — atalhos no teclado, ações em lote",
    "Ties Insights — enxergue baldes de empate",
    "Sem agentes — aproveite seu pipeline existente"
  ];

  const faqs = [
    {
      q: "Preciso trocar meu scanner?",
      a: "Não. Consumimos seus JSONs atuais e enriquecemos com fontes abertas."
    },
    {
      q: "O ranking é 'caixa-preta'?",
      a: "Não. Cada item traz o waterfall 5Q e a lista de critérios de desempate."
    },
    {
      q: "Como vocês evitam falsos positivos?",
      a: "Age-gating, verificação dinâmica, exposição real (Q2), impacto (Q3) e sinais externos (PoC/KEV/EPSS)."
    },
    {
      q: "Consigo adaptar aos meus SLAs e políticas?",
      a: "Sim. Pesos por pergunta, presets e filtros salváveis por domínio/ambiente."
    }
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
              <img
                src={logoSrc}
                alt="Q5 Sentinel Logo"
                className="h-24 w-24"
              />
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-primary/80 bg-clip-text text-transparent">Q5 Sentinel</h1>
                <p className="text-sm text-muted-foreground font-medium">
                  Priorização RPI 5Q
                </p>
              </div>
            </Link>
            <div className="flex items-center gap-4">
              <Link to="/dashboard">
                <Button variant="outline" size="sm">
                  Dashboard
                </Button>
              </Link>
              <ThemeToggle />
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative py-20 px-6 bg-gradient-to-br from-background via-background to-primary/5">
        <div className="container mx-auto max-w-6xl text-center">
          {/* <img
            src={logoSrc}
            alt="Q5 Sentinel Logo"
            className="h-64 w-64 mx-auto mb-8 drop-shadow-lg"
          /> */}

          <h1 className="text-5xl font-bold mb-6 bg-gradient-to-r from-primary to-primary/80 bg-clip-text text-transparent">
            Q5 Sentinel — priorize o que realmente importa, agora.
          </h1>

          <h2 className="text-xl text-muted-foreground max-w-4xl mx-auto mb-8 leading-relaxed">
            Dashboard de priorização inteligente que combina <strong>Exploitability</strong>, <strong>Exposição</strong>, <strong>Impacto</strong>, <strong>Fixabilidade</strong> e <strong>Urgência</strong> para cortar o ruído e acelerar a correção.
          </h2>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Button size="lg" className="text-lg px-8 py-6">
              <Calendar className="h-5 w-5 mr-2" />
              Agendar uma demo
            </Button>
            <Button variant="outline" size="lg" className="text-lg px-8 py-6">
              <Play className="h-5 w-5 mr-2" />
              Ver produto em ação
            </Button>
          </div>

          {/* Micro Provas Sociais */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-4xl mx-auto">
            <div className="flex items-center gap-2 justify-center">
              <CheckCircle className="h-5 w-5 text-green-500" />
              <span className="text-sm">Integra com seus scanners e bases abertas</span>
            </div>
            <div className="flex items-center gap-2 justify-center">
              <CheckCircle className="h-5 w-5 text-green-500" />
              <span className="text-sm">Zero agentes • Em minutos, não meses</span>
            </div>
            <div className="flex items-center gap-2 justify-center">
              <CheckCircle className="h-5 w-5 text-green-500" />
              <span className="text-sm">Explicabilidade por item</span>
            </div>
          </div>
        </div>
      </section>

      {/* O Problema */}
      <section className="py-20 px-6 bg-muted/30">
        <div className="container mx-auto max-w-4xl">
          <h2 className="text-4xl font-bold text-center mb-8">
            Backlog infinito, tempo finito.
          </h2>

          <p className="text-lg text-muted-foreground text-center mb-12 leading-relaxed">
            Scanners sinalizam milhares de findings. Sem contexto de exploração real, urgência e esforço, tudo vira "alta prioridade". O resultado? Falsos positivos no topo, SLAs estourando e times gastando horas onde não deveria.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card className="border-destructive/20 bg-destructive/5">
              <CardContent className="p-6 text-center">
                <AlertTriangle className="h-8 w-8 text-destructive mx-auto mb-4" />
                <h3 className="font-semibold mb-2">Muito ruído</h3>
                <p className="text-sm text-muted-foreground">
                  PoCs e KEV se perdem em meio a vulnerabilidades triviais.
                </p>
              </CardContent>
            </Card>

            <Card className="border-orange-500/20 bg-orange-500/5">
              <CardContent className="p-6 text-center">
                <Eye className="h-8 w-8 text-orange-500 mx-auto mb-4" />
                <h3 className="font-semibold mb-2">Sem "por que agora?"</h3>
                <p className="text-sm text-muted-foreground">
                  Listas planas não explicam o ranking.
                </p>
              </CardContent>
            </Card>

            <Card className="border-amber-500/20 bg-amber-500/5">
              <CardContent className="p-6 text-center">
                <Clock className="h-8 w-8 text-amber-500 mx-auto mb-4" />
                <h3 className="font-semibold mb-2">Gargalo humano</h3>
                <p className="text-sm text-muted-foreground">
                  Priorizar manualmente consome dias a cada ciclo.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* A Solução Q5 */}
      <section className="py-20 px-6">
        <div className="container mx-auto max-w-6xl">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">
              As 5 perguntas que resolvem a priorização.
            </h2>
            <p className="text-lg text-muted-foreground max-w-3xl mx-auto">
              Nosso modelo 5Q transforma dados brutos em decisão: <strong>Exploitability (Q1)</strong>, <strong>Exposição (Q2)</strong>, <strong>Impacto (Q3)</strong>, <strong>Fixabilidade (Q4)</strong> e <strong>Urgência (Q5)</strong>.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {qQuestions.map((q) => (
              <Card
                key={q.id}
                className={`transition-all duration-300 cursor-pointer ${q.bgColor} ${
                  hoveredQ === q.id ? 'scale-105 shadow-lg' : ''
                }`}
                onMouseEnter={() => setHoveredQ(q.id)}
                onMouseLeave={() => setHoveredQ(null)}
              >
                <CardHeader>
                  <CardTitle className={`${q.color} text-lg`}>
                    {q.title}
                  </CardTitle>
                  <p className="text-sm font-medium text-foreground">
                    {q.subtitle}
                  </p>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {q.description}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="text-center mt-12">
            <Button variant="outline" size="lg">
              Entender o modelo 5Q
              <ArrowRight className="h-4 w-4 ml-2" />
            </Button>
          </div>
        </div>
      </section>

      {/* Por que Q5 Sentinel */}
      <section className="py-20 px-6 bg-muted/30">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-4xl font-bold text-center mb-4">
            Menos ruído. Mais ação. SLA no verde.
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-16">
            {benefits.map((benefit, index) => (
              <div key={index} className="text-center">
                <div className="h-16 w-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-6">
                  <benefit.icon className="h-8 w-8 text-primary" />
                </div>
                <h3 className="text-xl font-semibold mb-4">{benefit.title}</h3>
                <p className="text-muted-foreground leading-relaxed">
                  {benefit.description}
                </p>
              </div>
            ))}
          </div>

          <div className="text-center mt-12">
            <Button size="lg">
              Ver como funciona
              <ArrowRight className="h-4 w-4 ml-2" />
            </Button>
          </div>
        </div>
      </section>

      {/* Como Funciona */}
      <section className="py-20 px-6">
        <div className="container mx-auto max-w-4xl">
          <h2 className="text-4xl font-bold text-center mb-4">
            Como funciona (em 90 segundos)
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-16">
            <div className="text-center">
              <div className="h-12 w-12 bg-primary rounded-full flex items-center justify-center mx-auto mb-6 text-primary-foreground font-bold text-lg">
                1
              </div>
              <h3 className="text-xl font-semibold mb-4">Conecte suas fontes</h3>
              <p className="text-muted-foreground">
                Suba JSONs do seu pipeline (SAST/DAST/IAST/runtime) e ative integrações abertas: KEV, EPSS, NVD, OSV.
              </p>
            </div>

            <div className="text-center">
              <div className="h-12 w-12 bg-primary rounded-full flex items-center justify-center mx-auto mb-6 text-primary-foreground font-bold text-lg">
                2
              </div>
              <h3 className="text-xl font-semibold mb-4">Ajuste o peso das perguntas</h3>
              <p className="text-muted-foreground">
                Arraste sliders dos pesos Q1..Q5. Presets prontos: "SLA-first", "Exploit-first", "Balanced".
              </p>
            </div>

            <div className="text-center">
              <div className="h-12 w-12 bg-primary rounded-full flex items-center justify-center mx-auto mb-6 text-primary-foreground font-bold text-lg">
                3
              </div>
              <h3 className="text-xl font-semibold mb-4">Decida</h3>
              <p className="text-muted-foreground">
                Use a tabela priorizada, drawer de detalhe e gráfico de Pareto para isolar o top-K.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Relatórios Inteligentes por Perfil */}
      <section className="py-20 px-6 bg-gradient-to-br from-primary/5 via-background to-primary/5">
        <div className="container mx-auto max-w-6xl">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">
              🎯 Relatórios que falam a sua língua
            </h2>
            <p className="text-xl text-muted-foreground max-w-4xl mx-auto">
              Imagine um sistema que entende exatamente quem está lendo e adapta a explicação em tempo real. <strong>CEO</strong> recebe resumos executivos de 30 segundos. <strong>Product Manager</strong> vê impacto no roadmap e experiência do usuário. <strong>Analista</strong> mergulha em detalhes técnicos profundos.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
            {/* CEO Profile */}
            <Card className="border-primary/20 bg-gradient-to-br from-primary/5 to-primary/10 hover:shadow-lg transition-all duration-300">
              <CardHeader className="text-center">
                <div className="h-16 w-16 bg-primary/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Users className="h-8 w-8 text-primary" />
                </div>
                <CardTitle className="text-primary text-xl">CEO</CardTitle>
                <p className="text-sm text-muted-foreground">Visão executiva • Impacto de negócio</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="bg-muted/50 p-4 rounded-lg">
                  <p className="text-sm font-medium mb-2">Exemplo de relatório:</p>
                  <p className="text-xs text-muted-foreground italic">
                    "A vulnerabilidade apresenta risco máximo (RPI 100) e severidade Critical. O impacto é total para o negócio, podendo comprometer operações críticas. O prazo de correção já venceu (-125 dias), com urgência máxima. Recomendamos atualizar imediatamente. (RPI=100.0, Prioridade=Critical)"
                  </p>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Leitura em 30 segundos</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Foco em ROI e riscos</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Decisões rápidas</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Product Manager Profile */}
            <Card className="border-blue-500/20 bg-gradient-to-br from-blue-500/5 to-blue-500/10 hover:shadow-lg transition-all duration-300">
              <CardHeader className="text-center">
                <div className="h-16 w-16 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Target className="h-8 w-8 text-blue-500" />
                </div>
                <CardTitle className="text-blue-500 text-xl">Product Manager</CardTitle>
                <p className="text-sm text-muted-foreground">Roadmap • Experiência do usuário</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="bg-muted/50 p-4 rounded-lg">
                  <p className="text-sm font-medium mb-2">Exemplo de relatório:</p>
                  <p className="text-xs text-muted-foreground italic">
                    "A vulnerabilidade impacta diretamente o PROJETOXYZ com RPI 100 e severidade Critical. Pode comprometer funcionalidades web e experiência do usuário. O prazo de correção expirou (-125 dias), exigindo ação imediata para manter a confiabilidade do produto. Recomendamos atualizar no roadmap de segurança."
                  </p>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Foco em produto e UX</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Impacto no roadmap</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Priorização estratégica</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Analyst Profile */}
            <Card className="border-purple-500/20 bg-gradient-to-br from-purple-500/5 to-purple-500/10 hover:shadow-lg transition-all duration-300">
              <CardHeader className="text-center">
                <div className="h-16 w-16 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Shield className="h-8 w-8 text-purple-500" />
                </div>
                <CardTitle className="text-purple-500 text-xl">Analista</CardTitle>
                <p className="text-sm text-muted-foreground">Detalhes técnicos • Profundidade</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="bg-muted/50 p-4 rounded-lg">
                  <p className="text-sm font-medium mb-2">Exemplo de relatório:</p>
                  <p className="text-xs text-muted-foreground italic">
                    "Relatório Técnico: A métrica Q1 apresenta exploitabilidade de 100.0, com PoC disponível e KEV ativo. EPSS score de 0.90887 (~91%) indica probabilidade elevada de ataque. O Q3 Impact é 100.0, com severidade Critical. SLA vencido em -125 dias. Correção imediata mandatória."
                  </p>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Análise técnica completa</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Métricas detalhadas</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Justificativas profundas</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* AI Power Section */}
          <Card className="border-primary/30 bg-gradient-to-r from-primary/10 to-primary/5">
            <CardContent className="p-8 text-center">
              <div className="flex items-center justify-center gap-3 mb-6">
                <Zap className="h-8 w-8 text-primary" />
                <h3 className="text-2xl font-bold text-primary">Powered by AI</h3>
                <Zap className="h-8 w-8 text-primary" />
              </div>
              <p className="text-lg text-muted-foreground mb-6 max-w-4xl mx-auto">
                Nossa integração com <strong>LLMs avançados</strong> analisa o contexto completo de cada vulnerabilidade e gera explicações personalizadas em tempo real. O sistema entende o grau de familiaridade técnica do usuário e adapta automaticamente o nível de detalhe, terminologia e foco da explicação.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
                <div className="text-center">
                  <div className="h-12 w-12 bg-primary/20 rounded-full flex items-center justify-center mx-auto mb-4">
                    <BarChart3 className="h-6 w-6 text-primary" />
                  </div>
                  <h4 className="font-semibold mb-2">Adaptação Inteligente</h4>
                  <p className="text-sm text-muted-foreground">
                    Detecta automaticamente o perfil e ajusta o conteúdo
                  </p>
                </div>
                <div className="text-center">
                  <div className="h-12 w-12 bg-primary/20 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Clock className="h-6 w-6 text-primary" />
                  </div>
                  <h4 className="font-semibold mb-2">Rapidez de Leitura</h4>
                  <p className="text-sm text-muted-foreground">
                    Otimiza o tempo de leitura baseado no cargo
                  </p>
                </div>
                <div className="text-center">
                  <div className="h-12 w-12 bg-primary/20 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Target className="h-6 w-6 text-primary" />
                  </div>
                  <h4 className="font-semibold mb-2">Foco no Essencial</h4>
                  <p className="text-sm text-muted-foreground">
                    Cada palavra conta para a decisão certa
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="text-center mt-12">
            <Button size="lg" className="bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary/70">
              <Users className="h-5 w-5 mr-2" />
              Experimente os Relatórios Personalizados
              <ArrowRight className="h-4 w-4 ml-2" />
            </Button>
          </div>
        </div>
      </section>

      {/* Call to Action - Test the Profiles */}
      <section className="py-16 px-6 bg-primary/10">
        <div className="container mx-auto max-w-4xl text-center">
          <h2 className="text-3xl font-bold mb-4">
            🚀 Pronto para revolucionar sua priorização?
          </h2>
          <p className="text-lg text-muted-foreground mb-8">
            Teste agora mesmo os relatórios inteligentes que se adaptam ao seu perfil. Selecione CEO, Product Manager ou Analista e veja a diferença.
          </p>
          <Link to="/dashboard">
            <Button size="lg" className="bg-primary hover:bg-primary/90 text-primary-foreground px-8 py-6 text-lg">
              <BarChart3 className="h-6 w-6 mr-2" />
              Acessar Dashboard e Testar Perfis
              <ArrowRight className="h-5 w-5 ml-2" />
            </Button>
          </Link>
        </div>
      </section>

      {/* Destaques do Produto */}
      <section className="py-20 px-6 bg-muted/30">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-4xl font-bold text-center mb-16">
            Destaques do produto
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {features.map((feature, index) => (
              <div key={index} className="flex items-start gap-3">
                <div className="h-6 w-6 bg-primary/20 rounded-full flex items-center justify-center mt-0.5">
                  <CheckCircle className="h-4 w-4 text-primary" />
                </div>
                <p className="text-muted-foreground leading-relaxed">
                  {feature}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Integrações */}
      <section className="py-20 px-6">
        <div className="container mx-auto max-w-4xl text-center">
          <h2 className="text-3xl font-bold mb-8">Integrações</h2>

          <div className="flex flex-wrap justify-center gap-3 mb-8">
            {integrations.map((integration) => (
              <Badge key={integration} variant="secondary" className="text-sm px-4 py-2">
                {integration}
              </Badge>
            ))}
          </div>

          <p className="text-muted-foreground leading-relaxed max-w-2xl mx-auto">
            O Q5 Sentinel cruza seus findings com bases públicas e sinais de ameaça.
            Tudo com cache local e política de privacidade clara. <strong>Sem enviar código-fonte.</strong>
          </p>
        </div>
      </section>

      {/* Aprendizado Inteligente */}
      <section className="py-20 px-6 bg-muted/30">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-4xl font-bold text-center mb-8">
            Aprendizado que Evolui com Seu Time
          </h2>
          <p className="text-xl text-center text-muted-foreground mb-16">
            O sistema aprende com cada decisão e se adapta automaticamente ao seu contexto
          </p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
            {/* Feedback Automático */}
            <Card className="border-blue-500/20 bg-blue-500/5">
              <CardHeader>
                <CardTitle className="text-blue-500 flex items-center gap-2">
                  <TrendingUp className="h-5 w-5" />
                  Feedback Automático
                </CardTitle>
                <p className="text-sm text-muted-foreground">
                  Cada ação no sistema vira lição para melhorar as próximas priorizações
                </p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-1" />
                    <div>
                      <p className="font-medium text-sm">Correções rápidas reforçam prioridades</p>
                      <p className="text-xs text-muted-foreground">Quando você resolve algo rápido, o sistema aprende que era realmente urgente</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-1" />
                    <div>
                      <p className="font-medium text-sm">Problemas recorrentes ajustam o foco</p>
                      <p className="text-xs text-muted-foreground">Issues que voltam sinalizam que o risco foi subestimado</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <Target className="h-4 w-4 text-amber-500 mt-1" />
                    <div>
                      <p className="font-medium text-sm">Decisões de aceitar risco</p>
                      <p className="text-xs text-muted-foreground">Quando você decide não corrigir, o sistema entende o contexto</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Personalização por Time */}
            <Card className="border-purple-500/20 bg-purple-500/5">
              <CardHeader>
                <CardTitle className="text-purple-500 flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  Personalização por Time
                </CardTitle>
                <p className="text-sm text-muted-foreground">
                  O sistema se adapta ao estilo e prioridades do seu time
                </p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div>
                    <p className="font-medium text-sm mb-2">Seu time, suas regras</p>
                    <p className="text-xs text-muted-foreground">
                      O sistema observa como vocês trabalham e ajusta as recomendações
                    </p>
                  </div>
                  <div className="bg-muted/50 p-3 rounded">
                    <p className="text-xs mb-2">
                      <strong>Times conservadores:</strong> Priorizam mais segurança, mesmo que custe mais
                    </p>
                    <p className="text-xs mb-2">
                      <strong>Times ágeis:</strong> Focam em impacto real e velocidade de correção
                    </p>
                    <p className="text-xs">
                      <strong>Times compliance:</strong> Seguem rigorosamente SLAs e regulamentações
                    </p>
                  </div>
                  <div>
                    <p className="font-medium text-sm">Melhoria contínua</p>
                    <p className="text-xs text-muted-foreground">
                      Quanto mais vocês usam, mais preciso fica
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Benefícios do Aprendizado */}
          <Card className="mt-12 border-primary/20 bg-primary/5">
            <CardHeader className="text-center">
              <CardTitle className="text-primary text-2xl">
                Por que isso importa?
              </CardTitle>
              <p className="text-muted-foreground">
                Não é só tecnologia — é inteligência que cresce com você
              </p>
            </CardHeader>
            <CardContent className="text-center">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
                <div className="text-center">
                  <div className="h-12 w-12 bg-primary/20 rounded-full flex items-center justify-center mx-auto mb-4">
                    <BarChart3 className="h-6 w-6 text-primary" />
                  </div>
                  <h4 className="font-semibold mb-2">Menos Falsos Positivos</h4>
                  <p className="text-sm text-muted-foreground">
                    Aprende quais alertas realmente importam para seu contexto
                  </p>
                </div>
                <div className="text-center">
                  <div className="h-12 w-12 bg-primary/20 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Clock className="h-6 w-6 text-primary" />
                  </div>
                  <h4 className="font-semibold mb-2">Decisões Mais Rápidas</h4>
                  <p className="text-sm text-muted-foreground">
                    Sugestões que já levam em conta seu histórico de decisões
                  </p>
                </div>
                <div className="text-center">
                  <div className="h-12 w-12 bg-primary/20 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Target className="h-6 w-6 text-primary" />
                  </div>
                  <h4 className="font-semibold mb-2">Alinhamento com Seu Time</h4>
                  <p className="text-sm text-muted-foreground">
                    Recomendações que fazem sentido para sua cultura e processos
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Segurança & Privacidade */}
      <section className="py-20 px-6">
        <div className="container mx-auto max-w-4xl">
          <h2 className="text-3xl font-bold text-center mb-4">
            Segurança & Privacidade
          </h2>
          <p className="text-xl text-center text-muted-foreground mb-12">
            Seu dado, suas regras.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="flex items-start gap-3">
              <Shield className="h-6 w-6 text-primary mt-0.5" />
              <div>
                <h3 className="font-semibold mb-1">Funcionamento offline/mocks para POCs</h3>
                <p className="text-sm text-muted-foreground">
                  Teste sem expor dados sensíveis
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <Eye className="h-6 w-6 text-primary mt-0.5" />
              <div>
                <h3 className="font-semibold mb-1">Modo leitura</h3>
                <p className="text-sm text-muted-foreground">
                  Não alteramos seus ambientes
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <Users className="h-6 w-6 text-primary mt-0.5" />
              <div>
                <h3 className="font-semibold mb-1">Controles de acesso</h3>
                <p className="text-sm text-muted-foreground">
                  Por função e trilhas de auditoria
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <Shield className="h-6 w-6 text-primary mt-0.5" />
              <div>
                <h3 className="font-semibold mb-1">Opções de deploy</h3>
                <p className="text-sm text-muted-foreground">
                  SaaS ou on-prem
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section className="py-20 px-6 bg-muted/30">
        <div className="container mx-auto max-w-4xl">
          <h2 className="text-3xl font-bold text-center mb-16">
            Perguntas frequentes
          </h2>

          <div className="space-y-6">
            {faqs.map((faq, index) => (
              <Card key={index}>
                <CardContent className="p-6">
                  <h3 className="font-semibold mb-3 text-lg">
                    {faq.q}
                  </h3>
                  <p className="text-muted-foreground leading-relaxed">
                    {faq.a}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Final */}
      <section className="py-20 px-6 bg-gradient-to-r from-primary/10 to-primary/5">
        <div className="container mx-auto max-w-4xl text-center">
          <h2 className="text-4xl font-bold mb-8">
            Pronto para priorizar com inteligência?
          </h2>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Button size="lg" className="text-lg px-8 py-6">
              <Calendar className="h-5 w-5 mr-2" />
              Quero priorizar melhor
            </Button>
            <Link to="/dashboard">
              <Button variant="outline" size="lg" className="text-lg px-8 py-6">
                <Users className="h-5 w-5 mr-2" />
                Testar Perfis IA
              </Button>
            </Link>
            <Button variant="outline" size="lg" className="text-lg px-8 py-6">
              <Play className="h-5 w-5 mr-2" />
              Assista ao tour de 2 minutos
            </Button>
          </div>

          <Link to="/dashboard">
            <Button variant="secondary" size="lg" className="mb-8">
              <BarChart3 className="h-5 w-5 mr-2" />
              Acessar Dashboard e Testar Perfis IA
            </Button>
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border bg-card/50 py-8 px-6">
        <div className="container mx-auto max-w-4xl">
          <div className="flex flex-col md:flex-row items-center justify-between">
            <div className="flex items-center gap-3 mb-4 md:mb-0">
              <img
                src={logoSrc}
                alt="Q5 Sentinel Logo"
                className="h-48 w-48"
              />
              <span className="font-semibold">© Q5 Sentinel — Foco no que importa.</span>
            </div>
            <div className="flex items-center gap-6 text-sm text-muted-foreground">
              <a href="#" className="hover:text-foreground transition-colors">Política de Privacidade</a>
              <a href="#" className="hover:text-foreground transition-colors">Termos de Uso</a>
              <a href="#" className="hover:text-foreground transition-colors">Contato</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Home;
