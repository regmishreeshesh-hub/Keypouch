# Managed Kubernetes Deployment (EKS/GKE/AKS)

This directory contains production-ready manifests for deploying Keypouch to a managed Kubernetes service.

## Key Changes from Local Setup
1. **Ingress**: Uses a single Ingress controller (`06-ingress.yaml`) to route traffic to both Frontend and Backend via hostnames.
2. **Resource Limits**: Configured CPU/Memory limits and requests for stability.
3. **Replicas**: Increased to 2 for High Availability.
4. **Storage**: PVC size increased to 20Gi (configurable in `02-pvc.yaml`).
5. **CORS**: Backend is configured to be more flexible (or should be locked down to the final domain).

## Deployment Steps

1. **Configure Domains**: 
   Open `01-configmap.yaml` and `06-ingress.yaml` and replace `yourdomain.com` with your actual domain.

2. **Database Initialization**:
   The `03-postgres.yaml` includes an init script ConfigMap. For very large databases or multi-region setups, consider using a managed DB like **Amazon RDS** or **GCP Cloud SQL** instead.

3. **Deploy**:
   You need a Docker Registry (ECR, GCR, DockerHub). 
   Run the helper script:
   ```bash
   chmod +x deploy.sh
   ./deploy.sh <your-registry-url> <tag>
   ```

## Ingress Controller
These manifests assume an **Nginx Ingress Controller** is installed in your cluster. 
If using EKS with AWS Load Balancer Controller, change the annotations in `06-ingress.yaml`.
