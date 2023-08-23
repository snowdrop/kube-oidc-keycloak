# Project to play with OIDC & SSO on kubernetes

A demo project to test how to configure a kubernetes cluster to [authenticate](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens) the users accessing the platform
using OIDC with a Keycloak OIDC provider.

The setup is not so complex, but it requires nevertheless to perform different steps such as:
- Generate a ROOT Ca certificate and key. This is needed to configure properly the ApiServer and Keycloak too
- Patch the `kubeadmConfigPatches` of kind config to specify the OIDC extra args:
  ```
  kind: ClusterConfiguration
    apiServer:
      extraArgs:
        oidc-client-id: kube
        oidc-issuer-url: https://$KEYCLOAK_HOSTNAME/realms/master
        oidc-username-claim: email
        oidc-groups-claim: groups
        oidc-ca-file: /etc/ca-certificates/keycloak/root-ca.pem
  ```
- Mount the CA certificate generated as `extraMounts` parameter to the kind config
- Create the kind cluster
- Install the certificate manager to generate OOTB for the keycloak ingress host the secret (using the root CA) to access the TLS endpoint
- Install keycloak with a Postgresql DB and expose it as an ingress host: `https://keycloak.127.0.0.1.nip.io` 
- Create a `kube` oidc client and set the client_id: kube and secret_id: kube-client-secret
- Add some users: user-dev, user-admin and groups: kube-dev, kube-admin
- Create on the cluster some clusterRoles: kube-admin, kube-dev having different RBAC: Cluster admin, edit, etc
- Assign a user to a keycloak group (e.g user-dev -> group: kube-dev). Such a mapping will allow in fact with the `id_token` returned as JWT from keycloak to get the group to which a user authenticated belongs:
  ```yaml
  # JWT Snippet from of the "user-admin" id_token
  "email": "user-admin@domain.com"
  "groups": [
    "kube-admin"
  ],
  ```
- Set for each user the OIDC auth provider credentials using the command: `kubectl config set-credentials user-dev --auth-provider=oidc ...` 
- Select one of the user and try to create different resources: `kubectl config use-context user-dev; kubectl create ns test`

To play the scenario using kind + keycloak and configure them, execute the following script: `./scripts/kind-oidc-keycloak.sh`

## Some useful References

- https://blogs.sap.com/2022/09/23/using-github-actions-openid-connect-in-kubernetes/
- https://dev.to/nuculabs_dev/kubernetes-openid-connect-integration-with-resource-owner-flow-ban
- https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens
- https://access.redhat.com/documentation/en-us/red_hat_codeready_workspaces/2.7/html/administration_guide/managing-identities-and-authorizations_crw#obtaining-the-token-from-openshift-token-through-keycloak_crw
- https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect

Kind OIDC + Keycloak

- https://medium.com/@charled.breteche/kind-keycloak-securing-kubernetes-api-server-with-oidc-371c5faef902
- https://faun.pub/kubernetes-auth-e2f342a5f269
