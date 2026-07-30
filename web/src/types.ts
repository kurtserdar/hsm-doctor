// Type mirrors of the Go API JSON payloads.

export interface ModuleInfo {
  path: string;
  cryptoki_version: string;
  manufacturer: string;
  description: string;
  library_version: string;
}

export interface TokenInfo {
  label: string;
  manufacturer: string;
  model: string;
  serial_number: string;
  hardware_version: string;
  firmware_version: string;
  initialized: boolean;
  login_required: boolean;
}

export interface SlotInfo {
  id: number;
  description: string;
  manufacturer: string;
  token_present: boolean;
  token?: TokenInfo;
}

export interface Mechanism {
  code: number;
  name: string;
  min_key_size?: number;
  max_key_size?: number;
  flags?: string[];
  hardware: boolean;
}

export interface DiscoverResponse {
  module: ModuleInfo;
  slots: SlotInfo[];
  mechanisms?: Record<number, Mechanism[]>;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  signature_algorithm: string;
  public_key_algorithm: string;
  is_ca: boolean;
}

export interface InventoryObject {
  class: string;
  label?: string;
  id?: string;
  key_type?: string;
  key_bits?: number;
  curve?: string;
  sensitive?: boolean;
  extractable?: boolean;
  sign?: boolean;
  verify?: boolean;
  encrypt?: boolean;
  decrypt?: boolean;
  wrap?: boolean;
  unwrap?: boolean;
  derive?: boolean;
  certificate?: CertInfo;
}

export interface Inventory {
  scanned_at: string;
  module: ModuleInfo;
  slot: SlotInfo;
  mechanisms: Mechanism[];
  logged_in: boolean;
  objects: InventoryObject[] | null;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  object?: string;
  detail?: string;
}

export interface VendorInfo {
  provider: string;
  experimental?: boolean;
  device?: {
    cpu_percent?: number;
    memory_percent?: number;
    disk_percent?: number;
    temperature_c?: number;
  };
  ha?: {
    group?: string;
    members?: { name: string; status: string; up: boolean }[];
  };
  partitions?: { label: string; used_objects?: number; used_storage_bytes?: number }[];
  tamper?: { tampered: boolean; detail?: string };
  extra?: Record<string, string>;
}

export interface ScanReport {
  tool: string;
  version: string;
  rule_packs?: string[];
  vendor?: VendorInfo;
  score: number;
  counts: {
    private_keys: number;
    public_keys: number;
    secret_keys: number;
    certificates: number;
  };
  findings: Finding[] | null;
  inventory: Inventory;
}

export type CertStatus = "ok" | "expiring" | "expired";

export interface CertEntry {
  label?: string;
  id?: string;
  subject: string;
  issuer: string;
  not_after: string;
  is_ca: boolean;
  status: CertStatus;
  days_left: number;
}

export interface CertsResponse {
  certificates: CertEntry[] | null;
  counts: { ok: number; expiring: number; expired: number };
  warn_days: number;
}

export interface TestStep {
  name: string;
  status: "PASS" | "FAIL" | "NOT SUPPORTED";
  detail?: string;
  duration_ns?: number;
}

export interface TestResult {
  profile: string;
  steps: TestStep[];
}

export interface BenchMeasurement {
  name: string;
  supported: boolean;
  ops: number;
  elapsed_ns: number;
  ops_per_sec: number;
  error?: string;
}

export interface BenchResult {
  options: { duration_ns: number; max_ops: number; sessions: number };
  measurements: BenchMeasurement[];
}

export interface ServerInfo {
  tool: string;
  version: string;
  mode: "local" | "central";
  oidc?: boolean;
  module?: ModuleInfo;
}

export interface HSMSummary {
  id: number;
  serial: string;
  label: string;
  model: string;
  manufacturer: string;
  firmware: string;
  module_path: string;
  slot_id: number;
  source: string;
  first_seen: string;
  last_seen: string;
  latest_score?: number;
  latest_scan_at?: string;
  latest_scan_id?: number;
}

export interface ScanSummary {
  id: number;
  hsm_id: number;
  taken_at: string;
  score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  private_keys: number;
  public_keys: number;
  secret_keys: number;
  certificates: number;
  report?: ScanReport;
}

export interface DriftDiff {
  token_changes?: { field: string; old: string; new: string }[];
  mechanisms_added?: string[];
  mechanisms_removed?: string[];
  objects_added?: string[];
  objects_removed?: string[];
  object_changes?: { object: string; field: string; old: string; new: string }[];
}

export interface PQCFamilyStatus {
  family: string;
  kind: string;
  fips: string;
  advertised: boolean;
  mechanisms?: string[];
  incomplete?: boolean;
}

export interface PQCResponse {
  detection: {
    cryptoki_version?: string;
    families: PQCFamilyStatus[];
    vendor_defined?: string[];
    verdict: "READY" | "PARTIAL" | "NOT READY";
  };
  exposure: {
    total_private_keys: number;
    classical_private_keys: number;
    pqc_private_keys: number;
    harvest_now_decrypt_later: number;
    classical_certificates: number;
    summary: string;
  };
  host_openssl?: {
    available: boolean;
    version?: string;
    ml_kem: boolean;
    ml_dsa: boolean;
    slh_dsa: boolean;
  };
  tests?: {
    family: string;
    set: string;
    status: string;
    detail?: string;
  }[];
}

export interface DriftEvent {
  id: number;
  hsm_id: number;
  detected_at: string;
  old_scan_id: number;
  new_scan_id: number;
  changes: number;
  diff: DriftDiff;
}
