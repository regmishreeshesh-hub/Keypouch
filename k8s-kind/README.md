# KeyPouch on a local kind cluster

This directory contains a kind-friendly Kubernetes manifest set:
- `Namespace`, `Secret`, `ConfigMap`
- `Postgres` (PVC + init SQL + Deployment + Service)
- `Backend` (Deployment + Service)
- `Frontend` (Deployment + Service)
- `Ingress` (routes `/api` → backend, `/` → frontend)

## Prereqs
- `kind`, `kubectl`, `docker`
- An Ingress controller in the cluster (these manifests assume **ingress-nginx**)

## 1) Create a kind cluster
```bash
kind create cluster --name keypouch
```

## 2) Install ingress-nginx (kind provider manifest)
```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
kubectl -n ingress-nginx rollout status deployment/ingress-nginx-controller
```

## 3) Build images and load them into kind
```bash
docker build -t keypouch/backend:kind ./backend
docker build -t keypouch/frontend:kind ./web

kind load docker-image keypouch/backend:kind --name keypouch
kind load docker-image keypouch/frontend:kind --name keypouch
```

## 4) Deploy KeyPouch
```bash
kubectl apply -k k8s-kind
kubectl -n keypouch rollout status deployment/keypouch-postgres
kubectl -n keypouch rollout status deployment/keypouch-backend
kubectl -n keypouch rollout status deployment/keypouch-frontend
```

## 5) Access it

Option A (works everywhere): port-forward the ingress controller
```bash
kubectl -n ingress-nginx port-forward svc/ingress-nginx-controller 8080:80
```
Then open:
- App: `http://localhost:8080/`
- API: `http://localhost:8080/api/health/live`

Default demo login (from DB init):
- username: `admin`
- password: `admin`

## Config
- `k8s-kind/01-secrets.yaml`: DB + JWT secrets
- `k8s-kind/02-configmap.yaml`: DB host, frontend API base (`/api`), CORS origins

## Cleanup
```bash
kind delete cluster --name keypouch
```
