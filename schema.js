const path = require('path')
const Hyperschema = require('hyperschema')

const dir = path.join(__dirname, 'spec', 'hyperschema')
const schema = Hyperschema.from(dir)
const ns = schema.namespace('securenv')

// Cleartext file header. The encoded header is also passed as additional
// data to the AEAD, so none of it can be changed without failing decryption.
ns.register({
  name: 'header',
  fields: [
    { name: 'version', type: 'uint', required: true },
    { name: 'algorithm', type: 'uint', required: true }, // crypto_pwhash alg
    { name: 'opslimit', type: 'uint', required: true },
    { name: 'memlimit', type: 'uint', required: true },
    { name: 'salt', type: 'fixed16', required: true },
    { name: 'nonce', type: 'fixed24', required: true }
  ]
})

ns.register({
  name: 'entry',
  fields: [
    { name: 'name', type: 'string', required: true },
    { name: 'value', type: 'buffer', required: true }
  ]
})

// The encrypted payload
ns.register({
  name: 'env',
  fields: [{ name: 'entries', type: '@securenv/entry', array: true, required: true }]
})

Hyperschema.toDisk(schema)
