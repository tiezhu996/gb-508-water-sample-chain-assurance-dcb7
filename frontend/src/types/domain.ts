
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
  id: number; seq: number | null; prevFingerprint: string; fingerprint: string;
  requestId: string; actor: string; action: string; entityType: string;
  entityId: number; beforeState: string; afterState: string; detail: string; createdAt: string;
}
export interface AuditChainEntry extends AuditLog { chainOk: boolean; issue?: string }
export type AuditChainIssueKind = 'unchained' | 'missing' | 'broken_link' | 'tampered' | 'anchor';
export interface AuditChainIssue {
  kind: AuditChainIssueKind; seq?: number; logId?: number;
  expected?: string; actual?: string; detail?: string;
}
export interface AuditChainStatus {
  intact: boolean; total: number; verifiedCount: number; lastSeq: number;
  genesisHash: string; anchorConsistent: boolean;
  firstIssue?: AuditChainIssue; issues: AuditChainIssue[];
}
export interface EntityConfig { key: string; path: string; label: string; statuses: readonly string[] }
