import apiClient from './client'
import type { ComplianceStatus, ComplianceSummaryStats } from '../types'

export async function fetchComplianceSummary(): Promise<ComplianceSummaryStats> {
  const res = await apiClient.get<ComplianceSummaryStats>('/compliance/summary')
  return res.data
}

export async function fetchCompliance(params: { compliance_status?: string; limit?: number; offset?: number } = {}): Promise<{ data: ComplianceStatus[]; total: number }> {
  const res = await apiClient.get<ComplianceStatus[]>('/compliance', { params })
  return {
    data: res.data,
    total: parseInt(res.headers['x-total-count'] || '0', 10),
  }
}

export async function fetchEndpointCompliance(endpointId: string): Promise<ComplianceStatus> {
  const res = await apiClient.get<ComplianceStatus>(`/compliance/${endpointId}`)
  return res.data
}

export async function triggerEvaluation(): Promise<void> {
  await apiClient.post('/compliance/evaluate')
}

export interface ComplianceDashboardData {
  summary: { total: number; compliant: number; partial: number; non_compliant: number; compliant_pct: number }
  issues: {
    no_edr: number; edr_outdated: number
    no_dlp: number; dlp_outdated: number
    no_wss: number; wss_outdated: number
    not_encrypted: number; no_device_control: number
    no_disk_encryption?: number; no_network_security?: number
  }
}

export async function fetchComplianceDashboard(): Promise<ComplianceDashboardData> {
  const res = await apiClient.get<ComplianceDashboardData>('/compliance/dashboard')
  return res.data
}
