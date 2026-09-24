# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
FROM python:3.12-slim
LABEL org.opencontainers.image.authors="Rahul Kumar <rahulk.3477@gmail.com>"
LABEL org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
USER 65532:65532
ENTRYPOINT ["sbom-convert"]
