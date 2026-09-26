
import { request } from './client';
import type { AuditChainEntry, AuditChainStatus } from '../types/domain';
export async function listAudits(page = 1, pageSize = 30) {
  return request<AuditChainEntry[]>(`/audits?page=${page}&pageSize=${pageSize}`);
}
export async function getAuditChain() {
  return request<AuditChainStatus>('/audit-chain');
}
export async function loadOverview() { return request<Record<string, Record<string, number>>>('/overview'); }
