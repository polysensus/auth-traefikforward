# Authorization helper

Integrates traefik ForwardAuth with a secure token exchange.

The requested audience for the new token is taken from the last URI segment.
The scopes are assumed to be configured in the client definition of the token
exchange.

# Tooling

## Usage from 1st checkout

1. clone the repo
2. task bootstrap NAMESPACE=yourchoice
   SKAFFOLD_DEFAULT_REPO defaults to eu.gcr.io/$(kubectl config current-context).
   If that doesn't suit, add SKAFFOLD_DEFAULT_REPO=yourchoice to the bootstrap
   overrides.
3. task generate CLIENTID_SECRET_FILE=path/to/clientidsecrets.env
  after the first run, you don't need to pass CLIENTID_SECRET_FILE again if
  re-generating other materials
4. task build
5. task deploy

## Manifests & cluster requirements

The kubernetes manifests assume the presence of a traefik proxy instance with
the kubernetes CRD provider enabled. If the RBAC rules don't allow the instance
to watch all namespaces, set the NAMESPACE variable to match treafiks when
bootstraping

If not using GCP, be sure to set SKAFFOLD_DEFAULT_REPO when bootstraping

## Taskfile conventions

The current kubernetes context when bootstraping is *sticky*. Tasks all set the
kubernetes context explicitly to the value recorded when bootstrap ran.
