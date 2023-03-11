# katsnet - kubernetes API on tailscale network

`katsnet` lets you use `kubectl` over Tailscale. It runs as an [impersonating
proxy](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)
inside of the cluster and joins your tailnet as a node.

## authorization

When your `kubectl` commands go through `katsnet`, they will appear with your Tailscale identity:

* for un-tagged nodes, Kubernetes will see your Tailscale login name (email) as
  the `User`; it will also see a group named `node:<name of the node you're
  connecting from>`
* for tagged nodes, Kubernetes will see groups named after the node tags, like
  `tag:prod`

You can use the standard Kubernetes RBAC policies to grant these User and Group
subjects permissions within the cluster. For example,
[user-rbac.yaml](user-rbac.yaml) grants the `admin` ClusterRole to my login
name when I connect from an untagged node like my laptop.

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
1. done, now you can run `kubectl` commands through the tailnet!

## generic setup

Generic setup is pretty much like the minikube setup with a few tweaks:

1. push the `katsnet` image to a registry you control
1. in `katsnet.yaml` set the Deployment image name to the one you pushed
1. in `katsnet.yaml` set `TS_HOSTNAME` to the name you want your Tailscale node
   to have

## security implications

Note that any process on any node within the tailnet can make k8s API requests
with this setup. `katsnet` doesn't do any additional authentication beyond
tailnet membership.

This means, for example, that you can open
`http://<katsnet-node-name>/api/v1/namespaces/kube-system/secrets` in the
browser and see all the secrets in `kube-system` namespace, as long as RBAC
allows you to. CORS _should_ prevent any random site from making such requests
on your behalf, but there could be possibilities for attackers triggering
requests from your machine.

So don't go running this in production just yet.
