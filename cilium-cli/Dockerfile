# syntax=docker/dockerfile:1.13@sha256:426b85b823c113372f766a963f68cfd9cd4878e1bcc0fda58779127ee98a28eb

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.23.5@sha256:8c10f21bec412f08f73aa7b97ca5ac5f28a39d8a88030ad8a339fd0a781d72b4
# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH

WORKDIR /go/src/github.com/cilium/cilium

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} DESTDIR=/out/${TARGETOS}/${TARGETARCH} $(echo $MODIFIERS | tr -d '"') \
    -C cilium-cli install

FROM docker.io/library/ubuntu:24.04@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab AS release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
WORKDIR /root/app
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/local/bin/cilium /usr/local/bin/cilium

# Install cloud CLIs. Based on these instructions:
# - https://cloud.google.com/sdk/docs/install#deb
# - https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
# - https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt#install-azure-cli
RUN apt-get update -y \
 && apt-get install -y curl gnupg unzip \
 && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
 && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - \
 && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
 && apt-get update -y \
 && apt-get install -y google-cloud-cli google-cloud-sdk-gke-gcloud-auth-plugin kubectl \
 && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
 && unzip awscliv2.zip \
 && ./aws/install \
 && rm -r ./aws awscliv2.zip \
 && curl -sL https://aka.ms/InstallAzureCLIDeb | bash

ENTRYPOINT []
