# Keep CNB's VS Code development environment and add Rizin's native build tools.
FROM cnbcool/default-dev-env:latest

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libcapstone-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && uv pip install --system --python /usr/local/bin/python3 \
        meson ninja PyYAML psutil requests \
    && meson --version \
    && ninja --version \
    && python3 -c 'import yaml, psutil, requests'
