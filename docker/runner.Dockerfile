# Minimal, hardened image that every sandboxed execution runs in.
#   docker build -f docker/runner.Dockerfile -t airlock-runner:latest .
FROM python:3.11-slim

# - remove package managers so code cannot `pip install` (and there is no network anyway)
# - strip setuid/setgid bits so there is nothing to escalate with
# - drop caches
RUN pip uninstall -y pip setuptools wheel >/dev/null 2>&1 || true \
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true \
 && rm -rf /var/lib/apt/lists/* /root/.cache /tmp/*

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Unprivileged user (nobody). The backend also forces this at `docker create` time.
USER 65534:65534
WORKDIR /tmp
CMD ["python"]
