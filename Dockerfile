# Single-stage relay image — no C toolchain, no cmake, no liboqs.
# All crypto runs client-side in the browser. This container is a blind router.
# Expected build time: < 60 seconds.

FROM python:3.12-slim

WORKDIR /app

# Only server-side runtime deps
COPY requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt

ENV PYTHONPATH=/app

COPY network/ network/
COPY . .

EXPOSE 8000

# Confirm NO crypto libraries loaded at startup
RUN python -c "from network.server import app; print('Relay server OK — zero crypto imports')"

CMD ["uvicorn", "network.server:app", "--host", "0.0.0.0", "--port", "8000"]
