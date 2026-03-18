# Storage Quotas

Limit storage per pod to prevent abuse and manage resources.

```bash
jss start --default-quota 50MB
```

## Managing Quotas

```bash
# Set quota for a user (overrides default)
jss quota set alice 100MB

# Show quota info
jss quota show alice
#   alice:
#     Used:  12.5 MB
#     Limit: 100 MB
#     Free:  87.5 MB
#     Usage: 12%

# Recalculate from actual disk usage
jss quota reconcile alice
```

## How It Works

- Quotas are tracked incrementally on PUT, POST, and DELETE operations
- When quota is exceeded, the server returns HTTP 507 Insufficient Storage
- Each pod stores its quota in `/{pod}/.quota.json`
- Use `reconcile` to fix quota drift from manual file changes

## Size Formats

Supported formats: `50MB`, `1GB`, `500KB`, `1TB`
