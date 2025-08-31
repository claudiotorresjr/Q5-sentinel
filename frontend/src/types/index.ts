/**
 * VulnDesk Type Definitions
 * Core types for vulnerability prioritization dashboard
 */

export type Vuln = {
  id: string;
  source_file?: string;
  vulnerability_ids?: string;  // ex: "CVE-2021-39144"
  product?: string;
  component_name?: string;
  version?: string;
  domain?: string;             // web_api, database, infra, backend, frontend, etc.
  environment?: string;        // prod | dev | test
  is_runtime?: boolean;
  is_dynamic?: boolean;
  is_static?: boolean;
  is_verified?: boolean;
  has_kev?: boolean;
  has_poc?: boolean;
  epss_score?: number;         // 0..1
  epss_percentile?: number;    // 0..100
  threat_heat?: number;        // 0..100
  cvss_base_score?: number;    // 0..10
  severity?: string;           // "critical" | "high" | ...
  criticality?: string;        // "critical" | "high" | ...
  nb_occurences?: number;
  nb_endpoints?: number;
  rpi_score: number;           // 0..100
  q1_exploitability?: number;  // 0..100
  q2_exposure?: number;        // 0..100
  q3_impact?: number;          // 0..100
  q4_fixability?: number;      // 0..100 (100 = easy)
  q5_urgency?: number;         // 0..100
  violates_sla?: boolean;
  sla_days_remaining?: number; // negative = violated
  effort_for_fixing?: number;  // relative cost
  has_jira_issue?: boolean;
  mitigation?: string;
  status?: 'open'|'mitigated'|'accepted'|'false_positive';
  scanner_confidence?: number; // 0..1
  tie_breaker_key?: string;    // debug
  reason_text?: string;        // explanations
};

export type Filters = {
  search?: string;
  has_kev?: boolean;
  has_poc?: boolean;
  epss_score_min?: number;
  epss_percentile_min?: number;
  is_verified?: boolean;
  is_dynamic?: boolean;
  is_static?: boolean;
  is_runtime?: boolean;
  confidence_min?: number;
  nb_occurences_min?: number;
  nb_endpoints_min?: number;
  domains?: string[];
  severities?: string[];
  environments?: string[];
  rpi_min?: number;
  rpi_max?: number;
  q4_min?: number;
  effort_max?: number;
  sla_violated?: boolean;
  sla_days_remaining_max?: number;
  hide_resolved?: boolean;
  status?: string[];
};

export type WeightConfig = {
  q1_weight: number;
  q2_weight: number;
  q3_weight: number;
  q4_weight: number;
  q5_weight: number;
  q1_enabled: boolean;
  q2_enabled: boolean;
  q3_enabled: boolean;
  q4_enabled: boolean;
  q5_enabled: boolean;
};

export type ParetoData = {
  target: number;
  k: number;
  coverage: number;
};

export type TiesData = {
  buckets: string[];
  groups: Array<{
    size: number;
    criteria: string;
    topsisAvg: number;
  }>;
};

export type HeroCounterData = {
  sla_violated: number;
  sla_warning: number;
  kev_count: number;
  poc_count: number;
  epss_high: number;
  total_count: number;
};