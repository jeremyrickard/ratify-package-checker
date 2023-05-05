# Build and Publish
CGO_ENABLED=0 GOOS=linux go build -o package-checker .
REPOSITORY=kubeconeu.azurecr.io/ratify/package-checker
oras push ${REPOSITORY}:v0.0.0-alpha.0 ./package-checker

# Register it with Ratify
kubectl apply -f package-verifier.yml

# Try it out
kubectl run demo --image=kubeconeu.azurecr.io/demo-app:sha-d0992af7eb825e7ba03fd777016073c3765a1c30