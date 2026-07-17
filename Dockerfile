# Pinned by digest: the tag can be re-pointed at any time, the digest cannot.
# Dependabot keeps this current (see .github/dependabot.yml).
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

# Install the toolkit as root, then drop privileges: a read-only scanner has no
# business running as root inside its own container.
WORKDIR /app
COPY pyproject.toml ./
COPY sentinel ./sentinel
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin sentinel \
    && mkdir -p /work/reports \
    && chown -R sentinel:sentinel /work

USER 10001
WORKDIR /work

# Reports land in /work/reports; mount a volume there to keep them.
ENTRYPOINT ["sentinel"]
CMD ["--help"]
