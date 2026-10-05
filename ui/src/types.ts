export interface RecordInfo {
  name: string;
  type: string;
  ttl: number;
  class: string;
  data: string;
  raw: string;
}

export interface HeaderFlags {
  qr: boolean;
  aa: boolean;
  tc: boolean;
  rd: boolean;
  ra: boolean;
  ad: boolean;
  cd: boolean;
}

export interface TraceHop {
  step: number;
  zone: string;
  server_name: string;
  server_ip: string;
  rtt: number; // nanoseconds in JSON, or converted to ms
  flags: HeaderFlags;
  rcode: number;
  rcode_str: string;
  authoritative: boolean;
  delegation: string[];
  glue: string[];
  answers: RecordInfo[];
  authority: RecordInfo[];
  additional: RecordInfo[];
  has_dnssec: boolean;
  rrsig_count: number;
  error?: string;
}

export interface TraceResult {
  domain: string;
  query_type: string;
  hops: TraceHop[];
  final_answers: RecordInfo[];
  total_rtt: number;
  success: boolean;
  cname_chain?: string[];
  error?: string;
}

export interface Provider {
  id: string;
  name: string;
  url: string;
  region: string;
  city: string;
  country: string;
  continent: string;
  anycast: boolean;
}

export interface NodeResult {
  provider: Provider;
  rtt: number;
  answers: RecordInfo[];
  matched_consensus: boolean;
  rcode: number;
  rcode_str: string;
  error?: string;
  ttl: number;
}

export interface PropagationSummary {
  domain: string;
  query_type: string;
  consensus_answers: string[];
  propagation_rate: number;
  total_tested: number;
  success_count: number;
  failed_count: number;
  min_rtt: number;
  max_rtt: number;
  avg_rtt: number;
  total_duration: number;
  results: NodeResult[];
}

export interface ChainNode {
  zone: string;
  status: 'SECURE' | 'BOGUS' | 'INSECURE' | 'INDETERMINATE';
  has_ds: boolean;
  ds_key_tags: number[];
  ds_digests: string[];
  has_dnskey: boolean;
  ksk_key_tags: number[];
  zsk_key_tags: number[];
  algorithms: string[];
  has_rrsig: boolean;
  signatures_valid: boolean;
  digest_matched: boolean;
  is_expired: boolean;
  inception?: string;
  expiration?: string;
  errors: string[];
  warnings: string[];
}

export interface ValidationResult {
  domain: string;
  query_type: string;
  overall_status: 'SECURE' | 'BOGUS' | 'INSECURE' | 'INDETERMINATE';
  chain: ChainNode[];
  errors: string[];
  warnings: string[];
  checked_at: string;
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'GOOD';

export interface Finding {
  category: string;
  title: string;
  description: string;
  severity: Severity;
  recommendation: string;
  record?: string;
}

export interface AuditReport {
  domain: string;
  score: number;
  grade: string;
  findings: Finding[];
  spf_status: string;
  dmarc_status: string;
  mx_status: string;
  takeover_risk: boolean;
  ns_consistency: boolean;
  checked_at: string;
}

export interface SummaryResult {
  domain: string;
  query_type: string;
  trace?: TraceResult;
  propagation?: PropagationSummary;
  dnssec?: ValidationResult;
  audit?: AuditReport;
  duration: number;
}
