# katsnet - kubernetes API on tailscale network

`katsnet` lets you use `kubectl` over Tailscale.

## minikube setup

For a local minikube setup:
1. build and push the katsnet image:
   ```
   minikube image build -t katsnet .
   ```
1. apply the base manifests:
   ```
   kubectl apply -f katsnet.yaml
   ```
1. create a secret with your [Tailscale auth key](https://tailscale.com/kb/1085/auth-keys/):
   ```
   kubectl create secret generic -n katsnet auth-key --from-literal=key=YOUR_AUTH_KEY
   ```
1. create k8s RBAC policies for your Tailscale identity, similar to [user-rbac.yaml](user-rbac.yaml)
1. update your `kubeconfig`:
   ```
   katsnet update-kubeconfig minikube
   # or
   go run main.go update-kubeconfig minikube
   ```
1. done!
