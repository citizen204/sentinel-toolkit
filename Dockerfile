FROM python:3.11-slim

WORKDIR /app

# Install the toolkit (build context copies only what the package needs).
COPY pyproject.toml ./
COPY sentinel ./sentinel
RUN pip install --no-cache-dir .

# Reports are written here; mount a volume to persist them.
WORKDIR /work
ENTRYPOINT ["sentinel"]
CMD ["--help"]
