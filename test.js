const test = require('brittle')
const fs = require('fs')
const path = require('path')
const b4a = require('b4a')
const sodium = require('sodium-native')
const SecureEnv = require('./')
const dotenv = require('./lib/dotenv')

const fast = {
  opslimit: sodium.crypto_pwhash_OPSLIMIT_MIN,
  memlimit: sodium.crypto_pwhash_MEMLIMIT_MIN
}

async function tmpFile(t) {
  return path.join(await t.tmp(), '.securenv')
}

test('create, set, flush, open', async function (t) {
  const file = await tmpFile(t)

  const env = await SecureEnv.create(file, 'hunter2', fast)
  env.set('API_KEY', 'secret')
  env.set('EMPTY', '')
  env.set('BIN', b4a.from([1, 2, 3]))
  await env.flush()
  env.close()

  const stat = fs.statSync(file)
  t.is(stat.size, 65536)
  t.is(stat.mode & 0o777, 0o600)
  t.alike(fs.readdirSync(path.dirname(file)), ['.securenv'], 'no tmp files left')
  t.is(fs.readFileSync(file).indexOf('secret'), -1)

  const env2 = await SecureEnv.open(file, b4a.from('hunter2'))
  t.is(env2.size, 3)
  t.alike([...env2.keys()], ['API_KEY', 'BIN', 'EMPTY'])
  t.is(b4a.toString(env2.get('API_KEY')), 'secret')
  t.is(env2.get('EMPTY').byteLength, 0)
  t.alike(b4a.from(env2.get('BIN')), b4a.from([1, 2, 3]))
  t.is(env2.get('NOPE'), null)

  t.ok(env2.delete('BIN'))
  await env2.flush()
  env2.close()

  const env3 = await SecureEnv.open(file, 'hunter2')
  t.is(env3.size, 2)
  t.absent(env3.has('BIN'))
  env3.close()
})

test('wrong password', async function (t) {
  const file = await tmpFile(t)
  const env = await SecureEnv.create(file, 'a', fast)
  env.close()

  await t.exception(SecureEnv.open(file, 'b'), /Wrong password/)
})

test('tampering with header or payload fails', async function (t) {
  const file = await tmpFile(t)
  const env = await SecureEnv.create(file, 'a', fast)
  env.close()

  const original = fs.readFileSync(file)

  // salt lives in the header, flipping it changes the key
  for (const offset of [8, 30, 100, original.byteLength - 1]) {
    const buf = b4a.from(original)
    buf[offset] ^= 1
    fs.writeFileSync(file, buf)
    await t.exception(SecureEnv.open(file, 'a'), 'offset ' + offset)
  }

  // lowering the kdf cost in the header must not be accepted either
  const buf = b4a.from(original)
  t.is(buf[2], fast.opslimit)
  buf[2]++
  fs.writeFileSync(file, buf)
  await t.exception(SecureEnv.open(file, 'a'))
})

test('pads to 64kb blocks and uses a fresh nonce per flush', async function (t) {
  const file = await tmpFile(t)
  const env = await SecureEnv.create(file, 'a', fast)

  const a = fs.readFileSync(file)
  await env.flush()
  const b = fs.readFileSync(file)

  t.is(a.byteLength, 65536)
  t.is(b.byteLength, 65536)
  t.unlike(a.subarray(100, 200), b.subarray(100, 200), 'ciphertext changed')

  env.set('BIG', b4a.alloc(65536))
  await env.flush()
  t.is(fs.statSync(file).size, 2 * 65536)

  // exactly fills the first block: header + env + marker + mac
  env.delete('BIG')
  env.set('X', b4a.alloc(1))
  await env.flush()
  t.is(fs.statSync(file).size, 65536)
  env.close()

  const env2 = await SecureEnv.open(file, 'a')
  t.is(env2.get('X').byteLength, 1)
  env2.close()
})

test('create does not overwrite, close zeroes', async function (t) {
  const file = await tmpFile(t)
  const env = await SecureEnv.create(file, 'a', fast)

  await t.exception(SecureEnv.create(file, 'a', fast), /exists/)

  env.set('A', 'value')
  const value = env.get('A')
  env.close()

  t.alike(b4a.from(value), b4a.alloc(5))
  t.exception(() => env.set('A', 'b'), /closed/)
  await t.exception(env.flush(), /closed/)
})

test('not a securenv file', async function (t) {
  const file = await tmpFile(t)
  fs.writeFileSync(file, 'FOO=bar\n')
  await t.exception(SecureEnv.open(file, 'a'))
})

test('find walks upwards', async function (t) {
  const root = await t.tmp()
  const nested = path.join(root, 'a', 'b', 'c')

  fs.mkdirSync(nested, { recursive: true })
  t.is(await SecureEnv.find(nested), null)

  fs.mkdirSync(path.join(root, 'a', 'b', '.securenv')) // directories are skipped
  fs.writeFileSync(path.join(root, 'a', '.securenv'), '')
  fs.writeFileSync(path.join(root, '.securenv'), '')

  t.is(await SecureEnv.find(nested), path.join(root, 'a', '.securenv'))
  t.is(await SecureEnv.find(root), path.join(root, '.securenv'))
})

test('dotenv parser', function (t) {
  const parse = (s) => dotenv(b4a.from(s)).map((e) => [e.name, b4a.toString(e.value)])

  t.alike(
    parse(
      [
        '﻿# comment',
        '',
        'PLAIN=value',
        '  SPACED =  a b c  ',
        'export EXPORTED=yes',
        'EMPTY=',
        'URL=https://example.com/?a=b#frag',
        "SINGLE='keeps \\n and $VAR and \" as is' # trailing comment",
        'DOUBLE="tab\\there \\"quoted\\" \\$5 back\\\\slash"',
        'MULTI="line one',
        'line two"',
        'CRLF=windows\r',
        'LAST=no newline'
      ].join('\n')
    ),
    [
      ['PLAIN', 'value'],
      ['SPACED', 'a b c'],
      ['EXPORTED', 'yes'],
      ['EMPTY', ''],
      ['URL', 'https://example.com/?a=b#frag'],
      ['SINGLE', 'keeps \\n and $VAR and " as is'],
      ['DOUBLE', 'tab\there "quoted" $5 back\\slash'],
      ['MULTI', 'line one\nline two'],
      ['CRLF', 'windows'],
      ['LAST', 'no newline']
    ]
  )

  t.alike(parse(''), [])
  t.alike(parse('\n# only comments\n'), [])

  const fails = (s, line) => {
    try {
      parse(s)
      t.fail('should have thrown: ' + s)
    } catch (err) {
      t.is(err.code, 'INVALID_DOTENV')
      t.is(err.line, line, err.message)
      t.absent(err.message.includes('hunter2'), 'value not in error')
    }
  }

  fails('OK=1\nno equals hunter2', 2)
  fails('1BAD=hunter2', 1)
  fails('=hunter2', 1)
  fails('A=1\n\nB="hunter2', 3)
  fails("A='hunter2", 1)
  fails('A="hunter2" trailing', 1)
  fails('A="hunter2\\x"', 1)
  fails('A=hunter2 # comment or value?', 1)
  fails('WITH-DASH=hunter2', 1)
})
