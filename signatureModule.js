var crypto = require('crypto')
var { v4 } = require('uuid')
var { importJWK, exportJWK } = require('jose')

const SIGNATURE_METHOD = 'GET'
const SIGNATURE_TARGET_URI = '/test'

const TEST_CLIENT = {
  id: v4(),
  name: 'Test Client',
  email: 'bob@bob.com',
  image: 'a link to an image',
  uri: 'https://example.com'
}

const TEST_CLIENT_DISPLAY = {
  name: TEST_CLIENT.name,
  uri: TEST_CLIENT.uri
}

// TODO: refactor any oustanding key-using tests to generate them from here
const BASE_TEST_KEY_JWK = {
  kty: 'OKP',
  alg: 'EdDSA',
  crv: 'Ed25519',
  key_ops: ['sign', 'verify'],
  use: 'sig'
}

async function generateTestKeys() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519')

  const { x, d } = await exportJWK(privateKey)
  const keyId = v4()
  return {
    keyId,
    publicKey: {
      ...BASE_TEST_KEY_JWK,
      kid: 'http://localhost:3000/keys/' + keyId,
      x
    },
    privateKey: {
      ...BASE_TEST_KEY_JWK,
      kid: 'http://localhost:3000/keys/' + keyId,
      x,
      d
    }
  }
}

async function generateSigHeaders(
  privateKey,
  url,
  method,
  body,
  authorization) {
  let sigInput = 'sig1=("@method" "@target-uri"'
  if (body) sigInput += ' "content-digest"'
  if (authorization) sigInput += ' "authorization"'
  sigInput += ');created=1618884473;keyid="gnap-key"'
  let challenge
  let contentDigest
  if (body) {
    const hash = crypto.createHash('sha256')
    hash.update(Buffer.from(JSON.stringify(body)))
    const bodyDigest = hash.digest()
    contentDigest = `sha-256:${bodyDigest.toString('base64')}:`
  }

  challenge = `"@method": ${method}\n"@target-uri": ${url}\n`
  if (body) challenge += `"content-digest": ${contentDigest}\n`
  if (authorization) challenge += `"authorization": ${authorization}\n`
  challenge += `"@signature-params": ${sigInput.replace(
    'sig1=',
    ''
  )}`

  const privateJwk = (await importJWK(privateKey))
  const signature = crypto.sign(null, Buffer.from(challenge), privateJwk)

  return { 
    headers: {
      'Signature': signature.toString('base64'),
      'Signature-Input': sigInput,
      'Content-Digest': contentDigest,
    },
    challenge
  }
}

module.exports = {
  generateTestKeys,
  generateSigHeaders
}
