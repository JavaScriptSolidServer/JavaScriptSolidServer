# Terminal & Password CLI

## WebSocket Terminal (`--terminal`)

Enable a WebSocket shell endpoint at `/.terminal` for browser-based terminal access.

```bash
jss start --terminal
```

### How it works

- Spawns `/bin/sh` per authenticated WebSocket connection
- Pipes stdin/stdout/stderr between WebSocket and shell
- Requires authentication (only authenticated users can connect)
- Disabled by default, opt-in via `--terminal`

### Environment variable

```bash
JSS_TERMINAL=true jss start
```

### Browser integration

Connect with [xterm.js](https://xtermjs.org/) or any WebSocket terminal client:

```javascript
const ws = new WebSocket('wss://your.pod/.terminal')
ws.onmessage = (e) => terminal.write(e.data)
terminal.onData((data) => ws.send(data))
```

### Security

- Authentication required — unauthenticated connections are rejected
- Experimental — not recommended for production multi-user servers without additional access controls
- Consider using `--single-user` mode for personal pod servers

## Password Management (`jss passwd`)

Manage IdP user passwords from the command line.

```bash
# Set password interactively
jss passwd <username>

# Set password directly
jss passwd <username> --password <newpassword>

# Generate and print a random password
jss passwd <username> --generate
```

### Options

| Flag | Description |
|------|-------------|
| `--password <pw>` | Set password non-interactively |
| `--generate` | Generate random password and print it |
| `-r, --root <path>` | Data directory (default: `./data`) |

### Examples

```bash
# Reset a user's password
jss passwd alice --password newsecretpass

# Generate a random password for a user
jss passwd bob --generate
# Output: New password for bob: a7Bx9kQ2mP...

# Interactive (prompts for password)
jss passwd alice
```
