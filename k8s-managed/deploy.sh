#!/bin/bash

# KeyPouch Cloud Deployment Script
# Usage: ./deploy.sh [registry-url] [tag]

set -e

REGISTRY=${1:-"your-registry.io/my-project"}
TAG=${2:-"latest"}
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K8S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }

if [ "$1" == "" ]; then
    echo "Usage: $0 <registry-url> [tag]"
    echo "Example: $0 gcr.io/my-project v1.0.0"
    exit 1
fi

log "Building and Pushing images to $REGISTRY..."

# Backend
log "Processing Backend..."
docker build -t "$REGISTRY/backend:$TAG" "$PROJECT_ROOT/backend"
docker push "$REGISTRY/backend:$TAG"

# Frontend
log "Processing Frontend..."
docker build -t "$REGISTRY/frontend:$TAG" "$PROJECT_ROOT/web"
docker push "$REGISTRY/frontend:$TAG"

log "Updating manifests with new images..."
# Note: Using sed to update image paths. In production, consider using Kustomize or Helm.
sed "s|image: backend:latest|image: $REGISTRY/backend:$TAG|g" "$K8S_DIR/04-backend.yaml" > "$K8S_DIR/04-backend.yaml.tmp"
sed "s|image: frontend:latest|image: $REGISTRY/frontend:$TAG|g" "$K8S_DIR/05-frontend.yaml" > "$K8S_DIR/05-frontend.yaml.tmp"

log "Applying manifests to cluster..."
kubectl apply -f "$K8S_DIR/00-base.yaml"
kubectl apply -f "$K8S_DIR/01-configmap.yaml"
kubectl apply -f "$K8S_DIR/02-pvc.yaml"
kubectl apply -f "$K8S_DIR/03-postgres.yaml"
kubectl apply -f "$K8S_DIR/04-backend.yaml.tmp"
kubectl apply -f "$K8S_DIR/05-frontend.yaml.tmp"
kubectl apply -f "$K8S_DIR/06-ingress.yaml"

rm "$K8S_DIR"/*.tmp

log "Deployment initiated. Check status with: kubectl get pods -n keypouch"
