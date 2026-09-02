import assert from 'node:assert/strict'
import { test } from 'node:test'

import { runAgentCall } from './call.mjs'

test('the independent Agent sends one bounded protected note and validates the result', async () => {
  let received
  const createFetch = (options) => {
    assert.equal(options.personServerUrl, 'https://service.example')
    assert.equal(options.getKeyMaterial instanceof Function, true)
    return async (target, init) => {
      received = { target, init }
      return new Response(JSON.stringify({
        note_id: 'note-1', person: 'interop-person', text: 'hello',
        replayed: false, consequence_count: 1,
      }), { status: 201, headers: { 'content-type': 'application/json' } })
    }
  }

  const result = await runAgentCall({
    agent: 'aauth:go-interop@interop.example',
    agent_token: 'agent-token',
    person_server: 'https://service.example',
    signing_key: { alg: 'Ed25519', crv: 'Ed25519', d: 'private', kid: 'agent-key-1', kty: 'OKP', x: 'public' },
  }, 'https://service.example/notes', 'write-1', 'hello', createFetch)

  assert.equal(received.target, 'https://service.example/notes')
  assert.equal(received.init.method, 'POST')
  assert.equal(received.init.headers['content-type'], 'application/json')
  assert.equal(received.init.body, '{"request_key":"write-1","text":"hello"}')
  assert.deepEqual(result, {
    agent: 'aauth:go-interop@interop.example',
    note_id: 'note-1', person: 'interop-person', replayed: false, consequence_count: 1,
  })
})
