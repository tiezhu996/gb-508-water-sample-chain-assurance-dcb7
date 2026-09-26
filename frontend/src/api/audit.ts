
import { request } from './client';
import type { AuditChainReport, AuditLog } from '../types/domain';
export async function listAudits(page = 1, pageSize = 30, search = '') {
  const query = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
  if (search.trim()) query.set('search', search.trim());
  return request<AuditLog[]>(`/audits?${query.toString()}`);
}
export async function getAuditChain() {
  return request<AuditChainReport>('/audit-chain');
}
export async function loadOverview() { return request<Record<string, Record<string, number>>>('/overview'); }
