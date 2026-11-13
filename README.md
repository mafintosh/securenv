# securenv

Password protected env files, based on libsodium.

```
npm install -g securenv
```

Secrets live in a `.securenv` file that is encrypted with a key derived from a password. The cli decrypts it and runs a command with each entry exposed as an env var.

## Usage

```sh
# add a secret, creates .securenv in the current dir if none is found
securenv --set API_KEY

# run a command with the secrets as env vars
securenv node server.js
```

`securenv` looks for a `.securenv` file in the current directory and walks upwards until it finds one. It always prints the path of the file it is using, then prompts for the password without echoing it.

## CLI

```
securenv [flags] [command] [...args]
```

Everything after the command is passed through to it untouched, and its exit code is passed back.

#### `securenv <command> [...args]`

Run `command` with every entry set as an env var. Entries override existing env vars with the same name.

#### `securenv --set|-s <name>`

Add or update an entry. The value is prompted for without echo, or read from stdin if stdin is piped:

```sh
pbpaste | securenv --set API_KEY
```

The value is never taken from the command line, so it stays out of your shell history and `ps`. If no `.securenv` file is found, one is created in the current directory and you are asked for a new password twice.

#### `securenv --unset|-u <name>`

Remove an entry.

#### `securenv --list|-l`

Print the entry names to stdout, one per line. Values are never printed.

#### `securenv --import|-i`

Set many entries at once from dotenv style lines on stdin, with a single unlock and write:

```sh
securenv --import < .env
```

Supported syntax:

```sh
NAME=value            # unquoted, runs to the end of the line, trimmed
NAME='value'          # literal, can span lines
NAME="value"          # \n \r \t \\ \" \$ escapes, can span lines
export NAME=value     # export prefix, comments and blank lines are fine
```

There is no variable expansion. Anything ambiguous, like a ` #` in an unquoted value, is rejected with the line number rather than guessed at, and nothing is written unless the full input parses.

#### `--file|-f <path>`

Use this file instead of searching for `.securenv`.

## Automation

Set `SECURENV_PASSWORD` to skip the password prompt:

```sh
SECURENV_PASSWORD=... securenv node server.js
echo "$TOKEN" | SECURENV_PASSWORD=... securenv --set TOKEN
```

The variable is not passed on to the command, and a wrong password fails right away instead of prompting. Note that an env var is weaker than the prompt, as it can be read by other processes of the same user and tends to end up in CI configs.

## API

```js
const SecureEnv = require('securenv')

const env = await SecureEnv.create('.securenv', password)

env.set('API_KEY', 'secret')
await env.flush()
env.close()
```

#### `const env = await SecureEnv.create(file, password, [options])`

Create a new env file. `password` is a buffer or string. Throws if the file exists.

```js
{
  overwrite: false, // replace an existing file
  opslimit, // argon2id ops limit, defaults to sodium's MODERATE
  memlimit // argon2id memory limit, defaults to sodium's MODERATE (256mb)
}
```

#### `const env = await SecureEnv.open(file, password)`

Open an existing env file. Throws an error with `code` set to `DECRYPTION_FAILED` if the password is wrong or the file was tampered with.

#### `const file = await SecureEnv.find(dir)`

Walk upwards from `dir` and return the path of the first `.securenv` file, or `null`.

#### `env.set(name, value)`

Set an entry. `value` is a buffer or string and is copied into secure memory.

#### `const value = env.get(name)`

Get an entry as a buffer, or `null`. The buffer is a view of secure memory that is zeroed when the entry is replaced or deleted, or the env is closed, so copy it if you need it for longer.

#### `const existed = env.delete(name)`

Delete an entry.

#### `env.has(name)`, `env.keys()`, `env.size`

Inspect the entries.

#### `await env.flush()`

Encrypt and write the entries to disk. Changes are only persisted when you call this. The file is written to a tmp file next to the target and renamed into place.

#### `env.close()`

Zero the key and all entries.

## File format

```
header | ciphertext | mac
```

- The header is a [hyperschema](https://github.com/holepunchto/hyperschema) struct with the format version, the argon2id parameters, a 16 byte salt and a 24 byte nonce.
- The key is derived from the password and salt with `crypto_pwhash` (argon2id).
- The entries are encoded as a hyperschema struct of `{ name, value }` pairs, padded and encrypted with `crypto_aead_xchacha20poly1305_ietf` using a fresh nonce on every write.
- The header is authenticated as additional data, so the parameters cannot be changed without failing decryption.
- The padding makes the full file a multiple of 64kb, so the size reveals very little about the contents.

The schema lives in `schema.js`, run `npm run schema` to regenerate `spec/`.

## Security notes

- The key, password and values are kept in sodium secure memory and zeroed after use. The exception is when running a command: the values have to become strings to be passed as env vars.
- A wrong password and a corrupted file are indistinguishable.
- The file is created with mode `0600`.

## License

Apache-2.0
