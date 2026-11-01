# The slow path: analyzer.live with the shipped tunnel model (LightGBM) and score fusion.
# The code and the models come from the checkout, mounted read-only at /dnsentinel.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir numpy==2.5.4 lightgbm==4.7.0
WORKDIR /dnsentinel
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "analyzer.live"]
