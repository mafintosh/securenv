const fs = require('fs')
const path = require('path')
const sodium = require('sodium-native')
const b4a = require('b4a')
const { resolveStruct } = require('./spec/hyperschema')

const Header = resolveStruct('@securenv/header')
const Env = resolveStruct('@securenv/env')

const VERSION = 1
const BLOCK_SIZE = 65536 // files are always a multiple of this
const PAD_MARKER = 0x80 // ISO/IEC 7816-4, marker byte followed by zeros

const KEYBYTES = sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
const NONCEBYTES = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
const MACBYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
const SALTBYTES = sodium.crypto_pwhash_SALTBYTES

const EMPTY = b4a.alloc(0)

module.exports = class SecureEnv {
  constructor(file, key, header, entries) {
    this.file = file
    this.closed = false

    this._key = key
    this._header = header // nonce is replaced on every flush
    this._entries = entries // name -> secure buffer
  }

  static FILENAME = '.securenv'

  // Walks upwards from dir and returns the first .securenv file found, or null
  static async find(dir) {
    dir = path.resolve(dir)

    while (true) {
      const file = path.join(dir, SecureEnv.FILENAME)

      try {
        if ((await fs.promises.stat(file)).isFile()) return file
      } catch {}

      const parent = path.dirname(dir)
      if (parent === dir) return null
      dir = parent
    }
  }

  static async create(file, password, opts = {}) {
    const {
      opslimit = sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      memlimit = sodium.crypto_pwhash_MEMLIMIT_MODERATE,
      overwrite = false
    } = opts

    if (!overwrite && (await exists(file))) {
      throw error('EXISTS', 'File already exists: ' + file)
    }

    const header = {
      version: VERSION,
      algorithm: sodium.crypto_pwhash_ALG_ARGON2ID13,
      opslimit,
      memlimit,
      salt: b4a.allocUnsafe(SALTBYTES),
      nonce: null
    }

    sodium.randombytes_buf(header.salt)

    const key = await deriveKey(password, header)
    const env = new SecureEnv(file, key, header, new Map())

    await env.flush()
    return env
  }

  static async open(file, password) {
    const buffer = await fs.promises.readFile(file)

    const state = { start: 0, end: buffer.byteLength, buffer }
    let header = null

    try {
      header = Header.decode(state)
    } catch {
      throw error('INVALID_FILE', 'Not a securenv file: ' + file)
    }

    if (header.version !== VERSION) {
      throw error('UNSUPPORTED_VERSION', 'Unsupported securenv version: ' + header.version)
    }

    const ad = buffer.subarray(0, state.start)
    const ciphertext = buffer.subarray(state.start)

    if (
      header.algorithm !== sodium.crypto_pwhash_ALG_ARGON2ID13 ||
      ciphertext.byteLength < MACBYTES + 1
    ) {
      throw error('INVALID_FILE', 'Not a securenv file: ' + file)
    }

    // copy so we do not retain the entire file buffer
    header.salt = b4a.from(header.salt)
    header.nonce = b4a.from(header.nonce)

    const key = await deriveKey(password, header)
    const plaintext = sodium.sodium_malloc(ciphertext.byteLength - MACBYTES)

    try {
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext,
        null,
        ciphertext,
        ad,
        header.nonce,
        key
      )
    } catch {
      sodium.sodium_memzero(key)
      throw error('DECRYPTION_FAILED', 'Wrong password or corrupted file')
    }

    const entries = new Map()

    try {
      const end = unpad(plaintext)
      const env = Env.decode({ start: 0, end, buffer: plaintext })

      for (const { name, value } of env.entries) {
        entries.set(name, secureCopy(value || EMPTY))
      }
    } catch {
      sodium.sodium_memzero(key)
      for (const value of entries.values()) sodium.sodium_memzero(value)
      throw error('INVALID_FILE', 'Corrupted securenv payload')
    } finally {
      sodium.sodium_memzero(plaintext)
    }

    return new SecureEnv(file, key, header, entries)
  }

  get size() {
    return this._entries.size
  }

  keys() {
    return this._entries.keys()
  }

  has(name) {
    return this._entries.has(name)
  }

  // Returns a view of secure memory, it is zeroed when the entry is replaced,
  // deleted or the env is closed. Copy it if you need it for longer.
  get(name) {
    const value = this._entries.get(name)
    return value === undefined ? null : value
  }

  set(name, value) {
    this._assertOpen()
    if (typeof name !== 'string' || name.length === 0) throw new Error('Name must be a string')

    const next = secureCopy(typeof value === 'string' ? b4a.from(value) : value)
    const prev = this._entries.get(name)

    if (prev) sodium.sodium_memzero(prev)
    this._entries.set(name, next)
  }

  delete(name) {
    this._assertOpen()

    const prev = this._entries.get(name)
    if (!prev) return false

    sodium.sodium_memzero(prev)
    return this._entries.delete(name)
  }

  async flush() {
    this._assertOpen()

    // fresh nonce on every write as the key is reused
    this._header.nonce = b4a.allocUnsafe(NONCEBYTES)
    sodium.randombytes_buf(this._header.nonce)

    const ad = encodeHeader(this._header)
    const entries = []

    for (const [name, value] of this._entries) entries.push({ name, value })
    entries.sort(cmp)

    const env = { entries }
    const state = { start: 0, end: 0, buffer: null }

    Env.preencode(state, env)

    // +1 for the pad marker, then round the full file up to the block size
    const unpadded = ad.byteLength + state.end + 1 + MACBYTES
    const total = Math.ceil(unpadded / BLOCK_SIZE) * BLOCK_SIZE

    const plaintext = sodium.sodium_malloc(total - ad.byteLength - MACBYTES)
    const out = b4a.allocUnsafe(total)

    try {
      plaintext.fill(0)
      state.buffer = plaintext
      Env.encode(state, env)
      plaintext[state.start] = PAD_MARKER

      out.set(ad, 0)
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.subarray(ad.byteLength),
        plaintext,
        ad,
        null,
        this._header.nonce,
        this._key
      )
    } finally {
      sodium.sodium_memzero(plaintext)
    }

    await writeAtomic(this.file, out)
  }

  close() {
    if (this.closed) return
    this.closed = true

    sodium.sodium_memzero(this._key)
    for (const value of this._entries.values()) sodium.sodium_memzero(value)
    this._entries.clear()
  }

  _assertOpen() {
    if (this.closed) throw error('CLOSED', 'SecureEnv is closed')
  }
}

function encodeHeader(header) {
  const state = { start: 0, end: 0, buffer: null }
  Header.preencode(state, header)
  state.buffer = b4a.allocUnsafe(state.end)
  Header.encode(state, header)
  return state.buffer
}

async function deriveKey(password, header) {
  const key = sodium.sodium_malloc(KEYBYTES)
  const pw = typeof password === 'string' ? b4a.from(password) : password

  await sodium.crypto_pwhash_async(
    key,
    pw,
    header.salt,
    header.opslimit,
    header.memlimit,
    header.algorithm
  )

  return key
}

function unpad(buffer) {
  let i = buffer.byteLength - 1
  while (i >= 0 && buffer[i] === 0) i--
  if (i < 0 || buffer[i] !== PAD_MARKER) throw new Error('Invalid padding')
  return i
}

function secureCopy(buffer) {
  const copy = sodium.sodium_malloc(buffer.byteLength)
  copy.set(buffer)
  return copy
}

function cmp(a, b) {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0
}

async function exists(file) {
  try {
    await fs.promises.stat(file)
    return true
  } catch {
    return false
  }
}

// Write to a tmp file next to the target and rename it into place, so a crash
// never leaves a partially written env behind.
async function writeAtomic(file, buffer) {
  const dir = path.dirname(file)
  const id = b4a.allocUnsafe(8)

  sodium.randombytes_buf(id)

  const tmp = path.join(dir, '.' + path.basename(file) + '.' + b4a.toString(id, 'hex') + '.tmp')

  const fd = await fs.promises.open(tmp, 'w', 0o600)

  try {
    let offset = 0
    while (offset < buffer.byteLength) {
      const { bytesWritten } = await fd.write(buffer.subarray(offset))
      offset += bytesWritten
    }

    await fd.sync()
    await fd.close()
    await fs.promises.rename(tmp, file)
  } catch (err) {
    await fd.close().catch(noop)
    await fs.promises.unlink(tmp).catch(noop)
    throw err
  }

  // best effort, persist the rename itself
  try {
    const d = await fs.promises.open(dir, 'r')
    await d.sync().catch(noop)
    await d.close()
  } catch {}
}

function error(code, message) {
  const err = new Error(message)
  err.code = code
  return err
}

function noop() {}
