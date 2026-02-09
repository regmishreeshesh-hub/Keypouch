#!/bin/bash

# KeyPouch Deployment Script
# Builds Docker images, loads to kind cluster, and deploys Kubernetes manifests

set -e

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K8S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="staging-cluster"
NAMESPACE="keypouch"
IMAGE_TAG="$(date +%Y%m%d-%H%M%S)"
BACKEND_IMAGE="keypouch/backend:$IMAGE_TAG"
FRONTEND_IMAGE="keypouch/frontend:$IMAGE_TAG"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check prerequisites
check_prereqs() {
    log "Checking prerequisites..."
    command -v docker >/dev/null || { error "Docker required"; exit 1; }
    command -v kind >/dev/null || { error "kind required"; exit 1; }
    command -v kubectl >/dev/null || { error "kubectl required"; exit 1; }
    kind get clusters | grep -q "$CLUSTER_NAME" || { error "Cluster '$CLUSTER_NAME' not found"; exit 1; }
    success "Prerequisites OK"
}

# Build Docker images
build_images() {
    log "Building Docker images with tag: $IMAGE_TAG"
    docker build -t "$BACKEND_IMAGE" "$PROJECT_ROOT/backend"
    docker build -t "$FRONTEND_IMAGE" "$PROJECT_ROOT/web"
    success "Images built with tag: $IMAGE_TAG"
}

# Load images to kind
load_images() {
    log "Loading images to kind cluster..."
    kind load docker-image "$BACKEND_IMAGE" --name "$CLUSTER_NAME"
    kind load docker-image "$FRONTEND_IMAGE" --name "$CLUSTER_NAME"
    success "Images loaded to kind"
}

# Deploy Kubernetes manifests
deploy_k8s() {
    log "Deploying to Kubernetes with image tag: $IMAGE_TAG"
    
    # Update image tags in deployment files (handles existing tags or :latest)
    sed -i.bak "s|keypouch/backend:[^\"]*|$BACKEND_IMAGE|g" "$K8S_DIR/backend-deployment.yaml"
    sed -i.bak "s|keypouch/frontend:[^\"]*|$FRONTEND_IMAGE|g" "$K8S_DIR/frontend-deployment.yaml"
    
    # Apply manifests in order
    kubectl apply -f "$K8S_DIR/namespace.yaml"
    kubectl apply -f "$K8S_DIR/secrets.yaml"
    kubectl apply -f "$K8S_DIR/configmap.yaml"
    kubectl apply -f "$K8S_DIR/persistent-volume-claim.yaml"
    kubectl apply -f "$K8S_DIR/init-script-configmap.yaml"
    kubectl apply -f "$K8S_DIR/postgres-deployment.yaml"
    kubectl apply -f "$K8S_DIR/postgres-service.yaml"
    kubectl apply -f "$K8S_DIR/backend-deployment.yaml"
    kubectl apply -f "$K8S_DIR/backend-service.yaml"
    kubectl apply -f "$K8S_DIR/frontend-deployment.yaml"
    kubectl apply -f "$K8S_DIR/frontend-service.yaml"
    
    # Wait for pods
    log "Waiting for pods to be ready..."
    kubectl wait --for=condition=ready pod -l app=keypouch,component=database -n "$NAMESPACE" --timeout=300s
    kubectl wait --for=condition=ready pod -l app=keypouch,component=backend -n "$NAMESPACE" --timeout=300s
    kubectl wait --for=condition=ready pod -l app=keypouch,component=frontend -n "$NAMESPACE" --timeout=300s
    
    success "Deployment completed with tag: $IMAGE_TAG"
}

# Port forwarding
port_forward() {
    log "Setting up port forwarding..."
    echo "Frontend: http://localhost:3002"
    echo "Backend: http://localhost:5001"
    echo "Press Ctrl+C to stop"
    
    # Kill any existing port-forwards
    pkill -f "kubectl port-forward.*keypouch" || true
    
    kubectl port-forward --address 0.0.0.0 service/keypouch-web-service 3002:3002 -n "$NAMESPACE" &
    FRONTEND_PID=$!
    
    kubectl port-forward --address 0.0.0.0 service/keypouch-backend-service 5001:5001 -n "$NAMESPACE" &
    BACKEND_PID=$!
    
    trap "kill $FRONTEND_PID $BACKEND_PID 2>/dev/null; log 'Port forwarding stopped'" EXIT
    wait
}

# Show help
show_help() {
    echo "Usage: $0 [deploy|build|load|forward|cleanup|status]"
}

# Main logic
case "${1:-deploy}" in
    "deploy")
        check_prereqs
        build_images
        load_images
        deploy_k8s
        ;;
    "build")
        build_images
        ;;
    "load")
        load_images
        ;;
    "forward")
        port_forward
        ;;
    "cleanup")
        kubectl delete -f "$K8S_DIR" --ignore-not-found=true
        ;;
    "status")
        kubectl get pods,svc -n "$NAMESPACE"
        ;;
    *)
        show_help
        exit 1
        ;;
esac
