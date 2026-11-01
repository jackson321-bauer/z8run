# Unix Socket Nodes

> z8-proxy3: interner Engine-Socket `/data/z8run/z8run.sock` spricht udsv3.
> `unix-out` erkennt `*z8run.sock` automatisch; `curl --unix-socket` allein
> funktioniert dort NICHT mehr (Chiffre). Andere lokale Sockets bleiben plain.

`Unix In` and `Unix Out` speak **HTTP/1.1 over a local Unix domain socket**.
No TCP port is opened, no TLS is involved, and nothing is reachable from the network.

The socket is a file on disk. Access is controlled by filesystem permissions.

## Requirements

- z8run must be started with `Z8_UDS_PATH`, for example:

  ```ini
  Z8_UDS_PATH=/data/z8run/z8run.sock
  ```

- The receiving and sending processes must be able to access the socket file.
  The server creates it with mode `0600`, owned by the z8run user.
  Run both processes as the same user, or as root.

- The service removes a stale socket file before binding. A crash does not
  leave a socket that blocks the next start.

## Unix In (trigger)

Receives HTTP requests on the Unix socket and starts the flow.

| Field    | Default | Meaning                              |
|----------|---------|--------------------------------------|
| `method` | `POST`  | HTTP method accepted by the route    |
| `path`   | `/echo` | Path below `/hook/<flow-id>/`        |

After **Start** (deploy), the route is:

```
/hook/<flow-id>/<path>
```

The node emits one message on `output` with the same structure as `HTTP In`:
method, path, query, headers, body.

## Unix Out (client)

Sends an HTTP request over the Unix socket and returns the response.

| Field              | Default                     | Meaning                                              |
|--------------------|-----------------------------|------------------------------------------------------|
| `socketPath`       | `/data/z8run/z8run.sock`    | Absolute path of the socket                          |
| `method`           | `POST`                      | GET, POST, PUT, PATCH, DELETE, HEAD                  |
| `path`             | `/hook/<flow-id>/echo`      | Request path                                         |
| `headers`          | `{}`                        | JSON object of request headers                       |
| `bodyPath`         | `payload`                   | Dot path in the message used as request body; empty = no body |
| `timeout`          | `5000`                      | Timeout in milliseconds                              |
| `maxResponseBytes` | `10485760`                  | Maximum response size (10 MB)                        |

Outputs:

- `output`: `{ "status": 200, "headers": {...}, "body": ... }`
  `body` is parsed JSON when possible, otherwise a string.
- `error`: error message when the connection fails, the timeout expires, or
  the response is larger than `maxResponseBytes`.

HTTP error statuses (404, 500, ...) are **normal responses** and appear on
`output`, not on `error`. Only transport failures go to `error`.

## Example

**Proxy-Engine** (receiver):

```
Unix In (POST /echo) -> HTTP Out (200)
```

**Kronvault-Engine** (caller):

```
Unix Out (socket /data/z8run/z8run.sock,
          path   /hook/<proxy-flow-id>/echo)
    -> Debug
```

Start the receiver first. Then start the caller.

## Manual test

```bash
# health over the socket
curl --unix-socket /data/z8run/z8run.sock http://localhost/api/v1/health

# trigger a deployed flow
curl -i --unix-socket /data/z8run/z8run.sock \
  -X POST http://localhost/hook/<flow-id>/echo

# unknown path -> 404
curl -i --unix-socket /data/z8run/z8run.sock \
  -X POST http://localhost/hook/<flow-id>/missing
```

## Security notes

- The socket is local-only. It cannot be reached over the network.
- Mode `0600` means only the owning user (and root) can connect.
- There is no TLS because the data never leaves the machine.
- The request body is limited by `maxResponseBytes` on the response side and
  by the HTTP layer on the request side.
- Do not place the socket in a world-writable directory.

## Limits

- One request per `Unix Out` execution; use a loop or multiple nodes for
  parallel calls.
- The socket path must be absolute.
- `Unix Out` does not follow redirects. A 3xx status is returned as-is.
