# Consuming the `gvm-mock-server` GHCR Image in CI

`rust-gvm` publishes a container image for tagged releases at:

- `ghcr.io/clawosiris/gvm-mock-server:<tag>`

Use an immutable release tag such as `v0.2.0` in downstream CI. Do not consume `latest` unless the release process is explicitly updated to publish it.

## Why use the image

The image gives downstream repositories a pinned mock GMP server without building Rust in every CI run. It is intended for integration tests against the standalone `gvm-mock-server` binary.

## Recommended pattern

Run the mock server over TCP inside the container and point your tests at that socket:

```bash
docker run --rm -d \
  --name gvm-mock \
  -p 127.0.0.1:9390:9390 \
  ghcr.io/clawosiris/gvm-mock-server:v0.2.0 \
  --mode stateful \
  --version 22.5 \
  --tcp 0.0.0.0:9390
```

Your tests can then connect to `127.0.0.1:9390`.

## GitHub Actions example

```yaml
jobs:
  integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Start mock GMP server
        run: |
          docker run --rm -d \
            --name gvm-mock \
            -p 127.0.0.1:9390:9390 \
            ghcr.io/clawosiris/gvm-mock-server:v0.2.0 \
            --mode stateful \
            --version 22.5 \
            --tcp 0.0.0.0:9390

      - name: Wait for server
        run: |
          for _ in $(seq 1 30); do
            if python3 - <<'PY'
import socket
sock = socket.create_connection(("127.0.0.1", 9390), timeout=1)
sock.close()
PY
            then
              exit 0
            fi
            sleep 1
          done
          echo "mock server did not start in time" >&2
          exit 1

      - name: Run integration tests
        env:
          GMP_HOST: 127.0.0.1
          GMP_PORT: "9390"
        run: make test-integration

      - name: Print mock server logs on failure
        if: failure()
        run: docker logs gvm-mock
```

## Other CI systems

The same pattern works in GitLab CI, Buildkite, CircleCI, or local developer workflows:

1. Pull `ghcr.io/clawosiris/gvm-mock-server:<tag>`.
2. Start the container with `--tcp 0.0.0.0:9390`.
3. Wait until port `9390` accepts connections.
4. Run your GMP integration tests against that address.

## Notes

- Prefer TCP in CI. Unix socket mounting is possible, but it is more runner-specific.
- The image entrypoint is `gvm-mock-server`, so pass normal CLI flags after the image name.
- Release tags are the compatibility boundary. Upgrade by changing the image tag in your CI config.
