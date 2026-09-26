
export interface DomainRecord {
  id: number;
  code: string;
  name: string;
  status: string;
  version: number;
  description: string;
  facility: string;
  owner: string;
  category: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  metricValue: number;
  metricUnit: string;
  effectiveAt: string;
  evidence: string;
  relatedCode: string;
  reviewRequestedBy?: string;
  peerReviewedBy?: string;
  signedBy?: string;
  createdAt: string;
  updatedAt: string;
}

export interface PageMeta { page: number; pageSize: number; total: number }
export interface ApiEnvelope<T> { data: T; error?: string; message?: string; meta?: PageMeta }
export interface UserSession { token: string; username: string; displayName: string; role: string; expiresIn: number }
export interface AuditLog {
  id: number;
  seq?: number | null;
  prevFingerprint?: string;
  fingerprint?: string;
  requestId: string; actor: string; action: string; entityType: string;
  entityId: number; beforeState: string; afterState: string; detail: string; createdAt: string;
}
export type AuditBreakReason = 'legacy' | 'gap' | 'tampered' | 'brokenLink';
export interface AuditChainBreak {
  seq: number;
  id: number;
  reason: AuditBreakReason;
  expectedFingerprint?: string;
  storedFingerprint?: string;
  expectedPrevFingerprint?: string;
  storedPrevFingerprint?: string;
}
export interface AuditChainReport {
  intact: boolean;
  total: number;
  verified: number;
  legacy: number;
  firstBreakSeq: number;
  firstBreakId: number;
  firstBreakReason?: AuditBreakReason;
  lastSeq: number;
  lastFingerprint?: string;
  breaks: AuditChainBreak[];
}
export interface EntityConfig { key: string; path: string; label: string; statuses: readonly string[] }
