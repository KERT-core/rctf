const CTRL_C = 0x03
const ESC = 0x1b
const DEL = 0x08
const BACKSPACE = 0x7f
const SPACE = 0x20
const SIGINT_EXIT_CODE = 130

// Reads a line without echoing it. Falls back to a plain read when stdin is
// not a TTY, so `rctf user set-password foo < secret` still works.
export const promptHidden = async (label: string): Promise<string> => {
  process.stdout.write(label)

  const stdin = process.stdin
  if (!stdin.isTTY) {
    for await (const line of console) return line
    return ''
  }

  stdin.setRawMode(true)
  stdin.resume()
  stdin.setEncoding('utf8')

  return await new Promise<string>(resolve => {
    let value = ''

    const restore = () => {
      stdin.removeListener('data', onData)
      stdin.setRawMode(false)
      stdin.pause()
      process.stdout.write('\n')
    }

    const onData = (chunk: string) => {
      // Arrow keys and friends arrive as one escape sequence; without this
      // their bytes land in the password.
      if (chunk.charCodeAt(0) === ESC) {
        return
      }

      for (const char of chunk) {
        if (char === '\r' || char === '\n') {
          restore()
          resolve(value)
          return
        }

        const code = char.charCodeAt(0)
        if (code === CTRL_C) {
          restore()
          process.exit(SIGINT_EXIT_CODE)
        }
        if (code === BACKSPACE || code === DEL) {
          value = value.slice(0, -1)
          continue
        }
        if (code < SPACE) {
          continue
        }
        value += char
      }
    }

    stdin.on('data', onData)
  })
}
