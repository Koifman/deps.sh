export type Ecosystem = 'npm' | 'pypi' | 'cargo';

export interface PackageInfo {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  maintainers: MaintainerInfo[];
  lastPublish: Date | null;
  dependencies: number;
  weeklyDownloads: number | null;
  installScripts: string[];
  repoUrl: string | null;
  description: string | null;
  ownershipTransfer: boolean;
  previousOwner?: string;
  currentOwner?: string;
}

export interface MaintainerInfo {
  name: string;
  email?: string;
}

export interface VulnInfo {
  id: string;
  summary: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  aliases: string[];
  affectedVersions: string[];
}

export interface GitHubInfo {
  stars: number;
  openIssues: number;
  lastCommit: Date | null;
  contributors: number;
  archived: boolean;
}

export interface RiskSignal {
  name: string;
  score: number;
  maxScore: number;
  detail: string;
}

export type RiskLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

export interface RiskReport {
  package: PackageInfo;
  vulnerabilities: VulnInfo[];
  github: GitHubInfo | null;
  signals: RiskSignal[];
  totalScore: number;
  level: RiskLevel;
  typosquatMatches: string[];
}

export interface EcosystemAdapter {
  ecosystem: Ecosystem;
  fetch(name: string, signal?: AbortSignal): Promise<PackageInfo>;
}

export interface RecentScanEntry {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  score: number;
  level: RiskLevel;
  signals: RiskSignal[];
  topRisks: string[];
}

export interface RecentScanResult {
  scannedAt: string | null;
  count: number;
  packages: RecentScanEntry[];
}

export interface SecurityFeedEntry {
  title: string;
  url: string;
  date: string;
  ecosystem: string;
  severity?: string;
}

export interface SecurityFeedResult {
  fetchedAt: string | null;
  entries: SecurityFeedEntry[];
}

export interface IncidentEntry {
  title: string;
  url: string;
  date: string;
  source: string;
}

export interface IncidentFeedResult {
  fetchedAt: string | null;
  entries: IncidentEntry[];
}

export interface TransferEntry {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  score: number;
  level: RiskLevel;
  previousOwner: string;
  currentOwner: string;
}

export interface TransferScanResult {
  scannedAt: string | null;
  count: number;
  packages: TransferEntry[];
}

export interface LockfileScanEntry {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  score: number;
  level: RiskLevel;
  topRisks: string[];
}

export interface LockfileScanResult {
  format: string;
  ecosystem: Ecosystem;
  totalPackages: number;
  scannedPackages: number;
  summary: { critical: number; high: number; moderate: number; low: number };
  packages: LockfileScanEntry[];
}
