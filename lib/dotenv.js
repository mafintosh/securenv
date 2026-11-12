const sodium = require('sodium-native')
const b4a = require('b4a')

const TAB = 0x09
const LF = 0x0a
const CR = 0x0d
const SPACE = 0x20
const DQUOTE = 0x22
const HASH = 0x23
const DOLLAR = 0x24
const SQUOTE = 0x27
const EQ = 0x3d
const BACKSLASH = 0x5c

const EXPORT = b4a.from('export')

// Strict dotenv parser. Works on bytes and returns the values in secure
// memory, so no secret ever becomes a js string. Supported syntax:
//
//   NAME=value            unquoted, runs to the end of the line, trimmed
//   NAME='value'          literal, can span lines
//   NAME="value"          \n \r \t \\ \" \$ escapes, can span lines
//   export NAME=value     # comments and blank lines are skipped
//
// There is no variable expansion and anything ambiguous is rejected with the
// line number (never the value) instead of guessed at.
module.exports = function parse(buffer) {
  const entries = []
  const n = buffer.byteLength
  const scratch = sodium.sodium_malloc(n || 1) // a value is never longer than the input

  let i = n >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf ? 3 : 0
  let line = 1

  try {
    while (true) {
      skipSpaces()
      if (i >= n) break

      if (buffer[i] === LF) {
        i++
        line++
        continue
      }

      if (buffer[i] === CR) {
        i++
        continue
      }

      if (buffer[i] === HASH) {
        skipLine()
        continue
      }

      if (startsWithExport()) {
        i += EXPORT.byteLength
        skipSpaces()
      }

      const start = i
      while (i < n && isName(buffer[i])) i++

      if (i === start || isDigit(buffer[start])) throw error(line, 'expected NAME=value')

      const name = b4a.toString(buffer.subarray(start, i))

      skipSpaces()
      if (i >= n || buffer[i] !== EQ) throw error(line, 'expected = after ' + name)
      i++
      skipSpaces()

      const startLine = line
      let length = 0

      if (i < n && buffer[i] === SQUOTE) {
        i++
        while (true) {
          if (i >= n) throw error(startLine, 'unterminated quote for ' + name)
          const byte = buffer[i++]
          if (byte === SQUOTE) break
          if (byte === LF) line++
          scratch[length++] = byte
        }
        endOfQuoted(name)
      } else if (i < n && buffer[i] === DQUOTE) {
        i++
        while (true) {
          if (i >= n) throw error(startLine, 'unterminated quote for ' + name)
          let byte = buffer[i++]
          if (byte === DQUOTE) break
          if (byte === LF) line++

          if (byte === BACKSLASH) {
            if (i >= n) throw error(startLine, 'unterminated quote for ' + name)
            byte = unescape(buffer[i++])
            if (byte === -1) throw error(line, 'unsupported escape sequence in ' + name)
          }

          scratch[length++] = byte
        }
        endOfQuoted(name)
      } else {
        while (i < n && buffer[i] !== LF) {
          const byte = buffer[i++]

          if (byte === HASH && length > 0 && isSpace(scratch[length - 1])) {
            throw error(line, 'ambiguous # in ' + name + ', quote the value')
          }

          scratch[length++] = byte
        }

        while (length > 0 && (isSpace(scratch[length - 1]) || scratch[length - 1] === CR)) length--
      }

      const value = sodium.sodium_malloc(length)
      value.set(scratch.subarray(0, length))
      entries.push({ name, value })
    }
  } catch (err) {
    for (const { value } of entries) sodium.sodium_memzero(value)
    throw err
  } finally {
    sodium.sodium_memzero(scratch)
  }

  return entries

  function skipSpaces() {
    while (i < n && isSpace(buffer[i])) i++
  }

  function skipLine() {
    while (i < n && buffer[i] !== LF) i++
  }

  function startsWithExport() {
    const end = i + EXPORT.byteLength
    return end < n && isSpace(buffer[end]) && b4a.equals(buffer.subarray(i, end), EXPORT)
  }

  // only whitespace or a comment may follow a closing quote
  function endOfQuoted(name) {
    skipSpaces()
    if (i < n && buffer[i] === CR) i++
    if (i < n && buffer[i] === HASH) skipLine()
    if (i < n && buffer[i] !== LF) throw error(line, 'unexpected characters after the value of ' + name)
  }
}

function unescape(byte) {
  switch (byte) {
    case 0x6e:
      return LF
    case 0x72:
      return CR
    case 0x74:
      return TAB
    case BACKSLASH:
    case DQUOTE:
    case DOLLAR:
      return byte
  }
  return -1
}

function isSpace(byte) {
  return byte === SPACE || byte === TAB
}

function isDigit(byte) {
  return byte >= 0x30 && byte <= 0x39
}

function isName(byte) {
  return isDigit(byte) || (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) || byte === 0x5f
}

function error(line, message) {
  const err = new Error('Invalid input on line ' + line + ': ' + message)
  err.code = 'INVALID_DOTENV'
  err.line = line
  return err
}
