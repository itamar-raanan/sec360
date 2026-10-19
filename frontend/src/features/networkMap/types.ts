export interface MapFloor {
  id: string
  ordinal: number
  label: string
  managed: boolean
}

export interface MapEquipment {
  id: string
  connection_id: string
  kind: 'ap' | 'switch'
  name: string
  floor_id: string | null
  position: { x: number; z: number }
  metadata: Record<string, unknown>
  port_overrides: Record<string, unknown>
  last_seen: string | null
}

export interface MapEndpoint {
  id: string | null
  hostname: string | null
  ip_address: string | null
  os_version: string | null
  username: string | null
  last_seen: string | null
  risk_score: number | null
  owner: string | null
  products: string[]
}

export interface MapAttachment {
  id: string
  mac_address: string
  attachment_type: 'wireless' | 'wired'
  equipment_id: string
  floor_id: string | null
  port: string | null
  vlan: string | null
  ssid: string | null
  state: string | null
  observed_at: string
  match_state: 'matched' | 'ambiguous' | 'no_current_match'
  candidate_endpoint_ids: string[]
  endpoint: MapEndpoint
}

export interface NetworkMapPayload {
  generated_at: string
  floors: MapFloor[]
  connections: Array<{ id: string; type: string; name: string; enabled: boolean; status: string; last_collected_at: string | null; last_error: string | null }>
  equipment: MapEquipment[]
  attachments: MapAttachment[]
  summary: { floors: number; building_floors: number; equipment: number; endpoints: number; matched: number; unassigned_equipment: number }
}
