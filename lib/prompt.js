const fs = require('fs')
const tty = require('tty')
const process = require('process')
const sodium = require('sodium-native')
const b4a = require('b4a')

const MAX_LENGTH = 4096

// Prompts for a password on the controlling terminal without echoing it.
// Resolves to a buffer in secure memory, the caller must sodium_memzero it.
// The password never touches a js string and input chunks are zeroed asap.
module.exports = function prompt(message) {
  const { input, owned } = openInput()

  return new Promise((resolve, reject) => {
    const buffer = sodium.sodium_malloc(MAX_LENGTH)
    let length = 0

    write(message)

    input.setRawMode(true)
    input.on('data', ondata)
    input.on('error', onerror)
    input.on('end', oncancel)
    input.resume()

    function ondata(data) {
      try {
        if (data[0] === 0x1b) return // arrow keys and friends

        for (let i = 0; i < data.byteLength; i++) {
          const byte = data[i]

          if (byte === 0x0d || byte === 0x0a) return done(null)
          if (byte === 0x03) return oncancel() // ctrl-c
          if (byte === 0x04 && length === 0) return oncancel() // ctrl-d

          if (byte === 0x7f || byte === 0x08) {
            // drop a full utf-8 character
            while (length > 0 && (buffer[--length] & 0xc0) === 0x80) buffer[length] = 0
            buffer[length] = 0
            continue
          }

          if (byte === 0x15) {
            // ctrl-u
            sodium.sodium_memzero(buffer)
            length = 0
            continue
          }

          if (byte < 0x20) continue
          if (length === MAX_LENGTH) return done(error('TOO_LONG', 'Password is too long'))

          buffer[length++] = byte
        }
      } finally {
        data.fill(0)
      }
    }

    function onerror(err) {
      done(err)
    }

    function oncancel() {
      done(error('CANCELLED', 'Cancelled'))
    }

    function done(err) {
      input.removeListener('data', ondata)
      input.removeListener('error', onerror)
      input.removeListener('end', oncancel)
      input.setRawMode(false)
      input.pause()

      if (owned) input.destroy()

      write('\n')

      if (err) {
        sodium.sodium_memzero(buffer)
        return reject(err)
      }

      const password = sodium.sodium_malloc(length)
      password.set(buffer.subarray(0, length))
      sodium.sodium_memzero(buffer)

      resolve(password)
    }
  })
}

function openInput() {
  // Talk to the terminal directly rather than through stdin. That leaves stdin
  // untouched for the child (it might be a pipe) and leaves no handle behind.
  // Note that even referencing process.stdin on bare starts consuming it.
  try {
    return { input: new tty.ReadStream(fs.openSync('/dev/tty', 'r')), owned: true }
  } catch {
    if (tty.isatty(0)) return { input: process.stdin, owned: false }
    throw error('NO_TTY', 'No terminal available to prompt for the password')
  }
}

// sync, so nothing is lost if the process exits right after
function write(message) {
  fs.writeSync(2, b4a.from(message))
}

function error(code, message) {
  const err = new Error(message)
  err.code = code
  return err
}
