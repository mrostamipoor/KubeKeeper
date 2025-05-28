#!/bin/bash

set -euo pipefail

# Install Kind if not present
if ! command -v kind &> /dev/null; then
  echo "Installing Kind..."
  curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
  chmod +x ./kind
  sudo mv ./kind /usr/local/bin/kind
fi

# Install Kubernetes v1.29.4 node image for Kind
K8S_VERSION="v1.29.4"
KIND_IMAGE="kindest/node:${K8S_VERSION}"

echo "Pulling Kind node image for Kubernetes ${K8S_VERSION}"
docker pull $KIND_IMAGE
