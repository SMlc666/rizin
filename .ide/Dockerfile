# SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only
# Keep CNB's VS Code development environment and add Rizin's native build tools.
FROM cnbcool/default-dev-env:latest

USER root

# The base image's Python is uv-managed; keep added Python tools in an isolated venv.
ENV VIRTUAL_ENV=/opt/rizin-venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libcapstone-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && uv venv --python /usr/local/bin/python3 "$VIRTUAL_ENV" \
    && uv pip install --python "$VIRTUAL_ENV/bin/python" \
        meson ninja PyYAML psutil requests \
    && meson --version \
    && ninja --version \
    && python -c 'import yaml, psutil, requests'
