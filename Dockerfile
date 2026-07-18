# Pinned by digest: the tag can be re-pointed at any time, the digest cannot.
# Dependabot keeps this current (see .github/dependabot.yml).
ARG BASE=python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

# --- build stage -------------------------------------------------------------
# Build tooling stays here. It never reaches the shipped image, so its CVEs are
# not our users' problem: setuptools vendors jaraco.* and wheel, which have had
# fixable HIGH advisories that a single-stage build would have shipped.
FROM ${BASE} AS builder
WORKDIR /app
COPY pyproject.toml requirements.lock ./
COPY sentinel ./sentinel
# The lock is applied as constraints, so the image gets the exact transitive
# versions that were tested rather than whatever resolves on build day.
RUN pip install --no-cache-dir --prefix=/install -c requirements.lock .

# --- runtime stage -----------------------------------------------------------
FROM ${BASE}
COPY --from=builder /install /usr/local

# A read-only scanner needs neither build tooling nor root.
RUN pip uninstall -y setuptools wheel \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin sentinel \
    && mkdir -p /work/reports \
    && chown -R sentinel:sentinel /work

USER 10001
WORKDIR /work

# Reports land in /work/reports; mount a volume there to keep them.
ENTRYPOINT ["sentinel"]
CMD ["--help"]
