# Deployment Proposal: Docker Compose

## Goal

Deploy each component as its own container under a single `docker-compose.yml`, with strict least-privilege defaults. No container should run as `root`, and images should drop elevated privileges as early as possible during startup.

## Principles

- **One service per component** (gateway, engine, policy, runner, broker, scheduler, audit, UI, worker).
- **Non-root users only**: each container runs as an unprivileged user.
- **Drop privileges early**: images may start as root only if absolutely required (e.g., to bind privileged ports or adjust filesystem permissions), then immediately switch to a non-root user before executing the app.
- **Read-only filesystems**: allow writable paths only where required.
- **No new privileges**: block privilege escalation.
- **Minimal capabilities**: drop all capabilities unless explicitly required.
- **Network segmentation**: separate internal services from external ingress.
- **Private device access**: use Tailscale (tailnet) so only the user’s devices can reach the Control UI.
- **Explicit secrets handling**: use Docker secrets or mounted files, not environment variables when possible.

## Proposed Services (Compose)

- `gateway`: external ingress, Control UI, pairing flow
- `engine`: LLM orchestration and planning
- `policy`: contract validation and gating
- `runner`: isolated tool execution
- `broker`: secrets broker
- `scheduler`: scheduled and event-driven jobs
- `audit`: append-only logging / storage
- `worker`: background tasks

## Security Baseline (Compose defaults)

- `user: "10001:10001"` or a named non-root user
- `read_only: true`
- `cap_drop: ["ALL"]`
- `security_opt: ["no-new-privileges:true"]`
- `tmpfs` mounts for `/tmp`
- `restart: unless-stopped`
- `healthcheck` per service

## Tailwind (Tailscale) Access Control

To ensure only the user’s devices can access the agent, run the gateway on a **Tailscale tailnet** and avoid public port exposure. Use Tailscale ACLs to allow access only from specific devices or users. This replaces public ingress with a private overlay network.

Key points:

- No `ports:` exposure for the gateway.
- Gateway binds to the tailnet interface only.
- ACLs restrict access to approved devices.

### Gateway-to-Services Connectivity (Internal Network)

Even when ingress is restricted to a tailnet, the gateway must still reach internal services (engine, policy, broker, etc.). The recommended pattern is:

- Keep **all services** on a private internal network.
- Do **not** publish gateway ports publicly.
- Use a Tailscale sidecar on the **same internal network** to proxy tailnet traffic to the gateway.
- Enforce **mTLS** or service-to-service auth between internal components.

This keeps the gateway reachable only via tailnet while preserving secure east‑west connectivity.

### Example: Tailscale Sidecar for Gateway

```yaml
services:
  tailscale:
    image: tailscale/tailscale:latest
    hostname: contractual-gateway
    environment:
      - TS_AUTHKEY=tskey-xxxxx
      - TS_STATE_DIR=/var/lib/tailscale
      - TS_USERSPACE=true
      - TS_SERVE_CONFIG=/config/serve.json
    volumes:
      - tailscale-state:/var/lib/tailscale
      - ./tailscale/serve.json:/config/serve.json:ro
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    networks:
      - internal

  gateway:
    image: contractual/gateway:latest
    user: "10001:10001"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /tmp
    networks:
      - internal
    depends_on:
      - tailscale

volumes:
  tailscale-state:
  
networks:
  internal:
    internal: true
```

Example `serve.json` (tailnet → gateway):

```json
{
  "TCP": {
    "443": {
      "HTTPS": true,
      "Handler": {
        "Proxy": "http://gateway:8080"
      }
    }
  }
}
```

## Example Compose Snippet

```yaml
services:
  gateway:
    image: contractual/gateway:latest
    user: "10001:10001"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /tmp
    ports:
      - "8080:8080"
    networks:
      - public
      - internal

  engine:
    image: contractual/engine:latest
    user: "10002:10002"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /tmp
    networks:
      - internal

  policy:
    image: contractual/policy:latest
    user: "10003:10003"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /tmp
    networks:
      - internal

  runner:
    image: contractual/runner:latest
    user: "10004:10004"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /tmp
    networks:
      - internal

  broker:
    image: contractual/broker:latest
    user: "10005:10005"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /tmp
    networks:
      - internal

  scheduler:
    image: contractual/scheduler:latest
    user: "10006:10006"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /tmp
    networks:
      - internal

  audit:
    image: contractual/audit:latest
    user: "10007:10007"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /tmp
    networks:
      - internal

  worker:
    image: contractual/worker:latest
    user: "10008:10008"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /tmp
    networks:
      - internal

networks:
  public:
  internal:
    internal: true
```

## Image-Level Guidance

- Create a non-root user and group in each Dockerfile (`useradd` or `adduser`).
- `chown` only necessary directories, then `USER appuser` before the entrypoint.
- If temporary root is needed during startup, drop privileges in the entrypoint (e.g., `su-exec` or `gosu`).
- Avoid running package managers or build steps in runtime images.

## Open Decisions

- Port mapping and TLS termination (gateway vs reverse proxy).
- Storage backend for audit log and artifacts.
- Secret storage strategy (Docker secrets vs external vault).
- Tailscale ACL policy design (per-user vs per-device access).
- Service-to-service mTLS bootstrapping (cert provisioning, rotation).
