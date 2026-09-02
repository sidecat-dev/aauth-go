import { readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'

import { createAAuthFetch } from '@aauth/agent'

export async function runAgentCall(config, resource, requestKey, text, createFetch = createAAuthFetch) {
  validateConfig(config)
  requireHTTPS(resource, 'Resource')
  if (!/^[!-~]{1,128}$/.test(requestKey)) throw new Error('request key must contain 1-128 visible ASCII characters')
  if (typeof text !== 'string' || text.length < 1 || text.length > 4096) throw new Error('note text must contain 1-4096 characters')

  const aauthFetch = createFetch({
    personServerUrl: config.person_server,
    getKeyMaterial: async () => ({
      signingKey: config.signing_key,
      signatureKey: { type: 'jwt', jwt: config.agent_token },
    }),
  })
  const response = await aauthFetch(resource, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': requestKey },
    body: JSON.stringify({ text }),
  })
  const body = await response.json()
  if (response.status !== 200 && response.status !== 201) {
    throw new Error(`Go Resource returned ${response.status}: ${JSON.stringify(body)}`)
  }
  if (typeof body.note_id !== 'string' || body.person !== 'interop-person' ||
      typeof body.replayed !== 'boolean' || body.consequence_count !== 1) {
    throw new Error(`Go Resource returned an invalid note result: ${JSON.stringify(body)}`)
  }
  return {
    agent: config.agent,
    note_id: body.note_id,
    person: body.person,
    replayed: body.replayed,
    consequence_count: body.consequence_count,
  }
}

function validateConfig(config) {
  if (!config || typeof config !== 'object') throw new Error('Agent config must be an object')
  if (typeof config.agent !== 'string' || !config.agent.startsWith('aauth:')) throw new Error('Agent config has no Agent identifier')
  if (typeof config.agent_token !== 'string' || config.agent_token.length === 0) throw new Error('Agent config has no Agent token')
  requireHTTPS(config.person_server, 'Person Server')
  const key = config.signing_key
  if (!key || key.kty !== 'OKP' || key.crv !== 'Ed25519' || key.alg !== 'Ed25519' ||
      typeof key.kid !== 'string' || typeof key.d !== 'string' || typeof key.x !== 'string') {
    throw new Error('Agent config has no complete Ed25519 signing JWK')
  }
}

function requireHTTPS(raw, label) {
  let parsed
  try {
    parsed = new URL(raw)
  } catch {
    throw new Error(`${label} must be an absolute HTTPS URL`)
  }
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password || parsed.hash) {
    throw new Error(`${label} must be an absolute HTTPS URL`)
  }
}

function argumentsOf(argv) {
  const values = {}
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index]
    const value = argv[index + 1]
    if (!name?.startsWith('--') || value === undefined) throw new Error('usage: node call.mjs --config PATH --resource URL --request-key KEY --text TEXT')
    values[name.slice(2)] = value
  }
  for (const name of ['config', 'resource', 'request-key', 'text']) {
    if (!values[name]) throw new Error('usage: node call.mjs --config PATH --resource URL --request-key KEY --text TEXT')
  }
  return values
}

async function main() {
  const args = argumentsOf(process.argv.slice(2))
  const config = JSON.parse(await readFile(args.config, 'utf8'))
  const result = await runAgentCall(config, args.resource, args['request-key'], args.text)
  process.stdout.write(`${JSON.stringify(result)}\n`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`aauth-ts-agent: ${error.message}\n`)
    process.exitCode = 1
  })
}
