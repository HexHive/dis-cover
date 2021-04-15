FROM python:3.9.4-slim-buster
WORKDIR /home/package_analysis
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    binutils \
    xz-utils \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
RUN pip install dis-cover
COPY analysis.py .
CMD ["python", "analysis.py"]
