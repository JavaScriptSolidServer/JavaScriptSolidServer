## MongoDB Storage (`/db/` Route)

Optional MongoDB-backed route for JSON-LD documents that need scale (social feeds, posts, follows). All other routes continue using the filesystem unchanged.

```bash
# Install the optional MongoDB driver
npm install mongodb

# Start with MongoDB enabled
jss start --mongo --mongo-url mongodb://localhost:27017 --mongo-database solid
```

### Operations

```bash
# Store a document
curl -X PUT http://localhost:4443/db/alice/notes/1 \
  -H "Content-Type: application/ld+json" \
  -H "Authorization: Bearer <token>" \
  -d '{"@context": "https://schema.org/", "@type": "Note", "text": "Hello"}'

# Read it back
curl http://localhost:4443/db/alice/notes/1

# List container (derived from URI prefixes)
curl http://localhost:4443/db/alice/

# Delete
curl -X DELETE http://localhost:4443/db/alice/notes/1 \
  -H "Authorization: Bearer <token>"
```

### How It Works

- `GET /db/:path` — retrieve a document by URI, or list a virtual container
- `PUT /db/:path` — create or update (upsert) a JSON-LD document
- `DELETE /db/:path` — remove a document
- Returns standard LDP headers (Link, ETag, WAC-Allow, CORS)
- Supports conditional requests (If-Match, If-None-Match)
- Container listings are computed from URI prefix queries — no directory management needed
- Auth: pod owner can write (`/db/{podName}/...`), reads are public
- MongoDB is an optional dependency — the server runs without it
