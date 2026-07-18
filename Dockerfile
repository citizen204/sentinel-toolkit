# Pinned by digest: the tag can be re-pointed at any time, the digest cannot.
# Dependabot keeps this current (see .github/dependabot.yml).
FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

# Install the toolkit as root, then drop privileges: a read-only scanner has no
# business running as root inside its own container.
WORKDIR /app
COPY pyproject.toml requirements.lock ./
COPY sentinel ./sentinel
# The lock file is applied as constraints, so the image gets the exact transitive
# versions that were tested rather than whatever resolved on build day. CI diffs
# the installed set against it, so drift fails the build instead of shipping.
RUN pip install --no-cache-dir -c requirements.lock . \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin sentinel \
    && mkdir -p /work/reports \
    && chown -R sentinel:sentinel /work

USER 10001
WORKDIR /work

# Reports land in /work/reports; mount a volume there to keep them.
ENTRYPOINT ["sentinel"]
CMD ["--help"]
