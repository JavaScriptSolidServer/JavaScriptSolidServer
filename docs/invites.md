# Invite-Only Registration

Control who can create accounts by requiring invite codes.

```bash
jss start --idp --invite-only
```

## Managing Invite Codes

```bash
# Create a single-use invite
jss invite create
# Created invite code: ABCD1234

# Create multi-use invite with note
jss invite create -u 5 -n "For team members"

# List all active invites
jss invite list
#   CODE        USES     CREATED      NOTE
#   -------------------------------------------------------
#   ABCD1234    0/1      2026-01-03
#   EFGH5678    2/5      2026-01-03   For team members

# Revoke an invite
jss invite revoke ABCD1234
```

## How It Works

| Mode | Registration | Pod Creation |
|------|--------------|--------------|
| Open (default) | Anyone can register | Anyone can create pods |
| Invite-only | Requires valid invite code | Via registration only |

When `--invite-only` is enabled:
- The registration page shows an "Invite Code" field
- Invalid or expired codes are rejected with an error
- Each use decrements the invite's remaining uses
- Depleted invites are automatically removed

Invite codes are stored in `.server/invites.json` in your data directory.
