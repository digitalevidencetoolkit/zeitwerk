# zeitwerk witness — optional container path.
#
# Prefer the systemd unit (deploy/zeitwerk-witness.service) where you can:
# fewer layers to audit, same result. This exists for shops whose policy
# requires containers.
#
#   docker build -t zeitwerk-witness -f deploy/Dockerfile .
#   docker run -d --name witness -p 127.0.0.1:14788:14788 \
#       -v zeitwerk-data:/data -v ~/.ssh/zeitwerk_deploy:/data/.ssh:ro \
#       zeitwerk-witness
#
# State (db, signer.pem, repo/) lives in the /data volume. Back it up.

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/zeitwerk
COPY pyproject.toml README.md LICENSE ./
COPY zeitwerk/ zeitwerk/
COPY submodules/python-opentimestamps/ submodules/python-opentimestamps/
RUN pip install --no-cache-dir ./submodules/python-opentimestamps . \
    && useradd --system --home-dir /data zeitwerk
USER zeitwerk
ENV HOME=/data
VOLUME /data
EXPOSE 14788

CMD ["python", "-m", "zeitwerk.server", "--data-dir", "/data", "--host", "0.0.0.0", "--port", "14788"]
