import assert from 'node:assert/strict'
import test from 'node:test'
import { endpointHasProduct } from '../src/utils/endpointProductPresence.ts'

test('S1, DLP and WSS presence comes from stored agents even without Compliance', () => {
  const endpoint = {
    agents: [
      { product_name: 'sentinelone', status: 'inactive' },
      { product_name: 'symantec', status: 'inactive' },
      { product_name: 'symantec_wss', status: 'active' },
    ],
    compliance_status: null,
    compliance_excluded: true,
    excluded_agents: ['symantec_dlp'],
  }
  for (const key of ['sentinelone', 'symantec_dlp', 'symantec_wss']) {
    assert.equal(endpointHasProduct(endpoint, key), true)
  }
})

test('an outdated Compliance snapshot cannot invent or hide installed products', () => {
  const endpoint = {
    agents: [{ product_name: 'symantec', status: 'inactive' }],
    compliance_status: {
      agent_presence: { sentinelone: true, symantec_dlp: false, symantec_wss: true },
    },
  }
  assert.equal(endpointHasProduct(endpoint, 'sentinelone'), false)
  assert.equal(endpointHasProduct(endpoint, 'symantec_dlp'), true)
  assert.equal(endpointHasProduct(endpoint, 'symantec_wss'), false)
})

test('Puppet inventory and missing agent arrays have deterministic presence', () => {
  assert.equal(endpointHasProduct({ puppet_managed: true }, 'puppet'), true)
  assert.equal(endpointHasProduct({ puppet_managed: false }, 'puppet'), false)
  assert.equal(endpointHasProduct({}, 'sentinelone'), false)
  assert.equal(endpointHasProduct({}, 'unknown'), false)
})
