#!/usr/bin/env node
const fs = require('fs')
const path = require('path')
const process = require('process')
const tty = require('tty')
const { spawn } = require('child_process')
const { command, flag, arg, rest, summary, description, bail } = require('paparam')
const sodium = require('sodium-native')
const b4a = require('b4a')
const SecureEnv = require('./')
const prompt = require('./lib/prompt')
const dotenv = require('./lib/dotenv')

const ATTEMPTS = 3
const PASSWORD_ENV = 'SECURENV_PASSWORD' // for automation, skips the prompt
const SIGNALS = { SIGHUP: 129, SIGINT: 130, SIGKILL: 137, SIGTERM: 143 }

const cmd = command(
  'securenv',
  summary('Run a command with the secrets of a .securenv file as env vars'),
  description(
    'Looks for a .securenv file in the current directory and upwards,\n' +
      'prompts for its password and runs the command with each entry exposed as an env var.\n' +
      'Set ' + PASSWORD_ENV + ' to skip the prompt, it is not passed on to the command.'
  ),
  flag('--file|-f [path]', 'Use this file instead of searching for .securenv'),
  flag('--set|-s <name>', 'Set an entry instead of running a command, the value is prompted for or read from stdin'),
  flag('--unset|-u <name>', 'Remove an entry instead of running a command'),
  flag('--list|-l', 'List the entry names instead of running a command'),
  flag('--import|-i', 'Set many entries from dotenv style NAME=value lines on stdin'),
  arg('[command]', 'Command to run'),
  rest('[...args]', 'Arguments passed to the command'),
  bail(usage),
  () => {
    const modes = ['set', 'unset', 'list', 'import'].filter((name) => cmd.flags[name])

    if (modes.length > 1) {
      return fatal(new Error('--' + modes[0] + ' cannot be combined with --' + modes[1]))
    }

    if (modes.length && cmd.args.command) {
      return fatal(new Error('--' + modes[0] + ' cannot be combined with a command'))
    }

    // exit explicitly, on bare the paused stdin from the prompt keeps the process alive
    if (cmd.flags.set) set().then(exit, fatal)
    else if (cmd.flags.unset) unset().then(exit, fatal)
    else if (cmd.flags.list) list().then(exit, fatal)
    else if (cmd.flags.import) importAll().then(exit, fatal)
    else run().catch(fatal)
  }
)

cmd.parse(process.argv.slice(2))

async function run() {
  if (!cmd.args.command) return usage({ reason: 'MISSING_ARG', arg: { value: '<command>' } })

  const file = cmd.flags.file ? path.resolve(cmd.flags.file) : await SecureEnv.find(process.cwd())

  if (!file) {
    throw new Error('No ' + SecureEnv.FILENAME + ' file found in ' + process.cwd() + ' or above')
  }

  log('securenv: using ' + file + '\n')

  const env = await unlock(file)
  const vars = { ...process.env }

  delete vars[PASSWORD_ENV] // never leak the password to the command

  for (const name of env.keys()) vars[name] = b4a.toString(env.get(name))
  env.close()

  let child = null

  try {
    child = spawn(cmd.args.command, cmd.rest || [], { stdio: 'inherit', env: vars })
  } catch (err) {
    return onspawnerror(err) // bare throws, node emits
  }

  // the terminal delivers ctrl-c to the child as well, let it decide what to do
  process.on('SIGINT', noop)
  process.on('SIGTERM', () => child.kill('SIGTERM'))
  process.on('SIGHUP', () => child.kill('SIGHUP'))

  child.on('error', onspawnerror)

  child.on('exit', (code, signal) => {
    process.exit(typeof code === 'number' ? code : SIGNALS[signal] || 1)
  })
}

async function set() {
  const name = cmd.flags.set


  const env = await openOrCreate()

  const value = tty.isatty(0)
    ? await prompt('securenv: value for ' + name + ': ')
    : await readStdin()

  try {
    const existed = env.has(name)
    env.set(name, value)
    await env.flush()
    log('securenv: ' + (existed ? 'updated ' : 'added ') + name + '\n')
  } finally {
    sodium.sodium_memzero(value)
    env.close()
  }
}

async function importAll() {
  if (tty.isatty(0)) throw new Error('--import reads NAME=value lines from stdin, pipe them in')

  // parse before unlocking so bad input fails before any password is asked for
  const input = await readStdin()
  let entries = null

  try {
    entries = dotenv(input)
  } finally {
    sodium.sodium_memzero(input)
  }

  let env = null

  try {
    if (entries.length === 0) throw new Error('No entries found on stdin')

    env = await openOrCreate()

    let added = 0
    let updated = 0

    for (const { name, value } of entries) {
      if (env.has(name)) updated++
      else added++
      env.set(name, value)
    }

    await env.flush()
    log('securenv: imported ' + added + ' added, ' + updated + ' updated\n')
  } finally {
    for (const { value } of entries) sodium.sodium_memzero(value)
    if (env) env.close()
  }
}

async function openOrCreate() {
  let file = cmd.flags.file ? path.resolve(cmd.flags.file) : await SecureEnv.find(process.cwd())

  if (file && (await exists(file))) {
    log('securenv: using ' + file + '\n')
    return unlock(file)
  }

  if (!file) file = path.join(process.cwd(), SecureEnv.FILENAME)
  log('securenv: creating ' + file + '\n')
  return create(file)
}

async function unset() {
  const name = cmd.flags.unset


  const file = cmd.flags.file ? path.resolve(cmd.flags.file) : await SecureEnv.find(process.cwd())

  if (!file) {
    throw new Error('No ' + SecureEnv.FILENAME + ' file found in ' + process.cwd() + ' or above')
  }

  log('securenv: using ' + file + '\n')

  const env = await unlock(file)

  try {
    if (!env.delete(name)) throw new Error('No entry named ' + name)
    await env.flush()
    log('securenv: removed ' + name + '\n')
  } finally {
    env.close()
  }
}

// Names only, on stdout so it can be piped. Values are never printed.
async function list() {

  const file = cmd.flags.file ? path.resolve(cmd.flags.file) : await SecureEnv.find(process.cwd())

  if (!file) {
    throw new Error('No ' + SecureEnv.FILENAME + ' file found in ' + process.cwd() + ' or above')
  }

  log('securenv: using ' + file + '\n')

  const env = await unlock(file)
  const names = [...env.keys()].sort()

  env.close()

  if (names.length) fs.writeSync(1, b4a.from(names.join('\n') + '\n'))
}

async function create(file) {
  const preset = envPassword()

  if (preset) {
    log('securenv: using password from ' + PASSWORD_ENV + '\n')

    try {
      return await SecureEnv.create(file, preset)
    } finally {
      sodium.sodium_memzero(preset)
    }
  }

  const password = await prompt('securenv: new password: ')
  const repeat = await prompt('securenv: repeat password: ')

  try {
    if (password.byteLength === 0) throw new Error('Password cannot be empty')

    if (password.byteLength !== repeat.byteLength || !sodium.sodium_memcmp(password, repeat)) {
      throw new Error('Passwords do not match')
    }

    return await SecureEnv.create(file, password)
  } finally {
    sodium.sodium_memzero(password)
    sodium.sodium_memzero(repeat)
  }
}

// Reads the value from piped stdin, minus one trailing newline
function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = []

    process.stdin.on('data', (data) => chunks.push(data))
    process.stdin.on('error', reject)
    process.stdin.on('end', () => {
      const all = b4a.concat(chunks)
      let end = all.byteLength

      if (end > 0 && all[end - 1] === 0x0a) end--
      if (end > 0 && all[end - 1] === 0x0d) end--

      const value = sodium.sodium_malloc(end)
      value.set(all.subarray(0, end))

      all.fill(0)
      for (const chunk of chunks) chunk.fill(0)

      resolve(value)
    })
  })
}

async function exists(file) {
  try {
    await fs.promises.stat(file)
    return true
  } catch {
    return false
  }
}

function onspawnerror(err) {
  if (err.code !== 'ENOENT') return fatal(err)
  log('securenv: command not found: ' + cmd.args.command + '\n')
  process.exit(127)
}

async function unlock(file) {
  const preset = envPassword()

  if (preset) {
    log('securenv: using password from ' + PASSWORD_ENV + '\n')

    try {
      return await SecureEnv.open(file, preset)
    } finally {
      sodium.sodium_memzero(preset)
    }
  }

  for (let i = 0; i < ATTEMPTS; i++) {
    const password = await prompt('securenv: password: ')

    try {
      return await SecureEnv.open(file, password)
    } catch (err) {
      if (err.code !== 'DECRYPTION_FAILED' || i === ATTEMPTS - 1) throw err
      log('securenv: wrong password, try again\n')
    } finally {
      sodium.sodium_memzero(password)
    }
  }
}

function envPassword() {
  const value = process.env[PASSWORD_ENV]
  if (!value) return null

  const bytes = b4a.from(value)
  const password = sodium.sodium_malloc(bytes.byteLength)

  password.set(bytes)
  bytes.fill(0)

  return password
}

function usage(bail) {
  const what = bail.flag ? ': ' + bail.flag.name : bail.arg ? ': ' + bail.arg.value : ''
  log('securenv: ' + bail.reason + what + '\n' + cmd.help() + '\n')
  process.exit(1)
}

// sync, so nothing is lost when we exit right after
function log(message) {
  fs.writeSync(2, b4a.from(message))
}

function exit() {
  process.exit(0)
}

function fatal(err) {
  log('securenv: ' + err.message + '\n')
  process.exit(err.code === 'CANCELLED' ? 130 : 1)
}

function noop() {}
