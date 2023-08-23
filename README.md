***REMOVED*** Project to test OIDC & SSO

A demo project to test how to configure a kubernetes cluster to [authenticate](https://kubernetes.io/docs/reference/access-authn-authz/authentication/***REMOVED***openid-connect-tokens) the users accessing the platform
using OIDC with a Keycloak OIDC provider.

The setup is not so complex, but it requires nevertheless to perform different steps such as:
- Generate a ROOT Ca certificate and key. This is needed to configure properly the ApiServer and Keycloak too
- Patch the `kubeadmConfigPatches` of kind config to specify the OIDC extra args
- Install the certificate manager to generate OOTB for the keycloak ingress host the secret (using the root CA) to access the TLS endpoint
- Install keycloak and create some users: user-dev, user-admin and groups: kube-dev, kube-admin
- Create some clusterRoles (kube-admin, kube-dev) having different RBAC: Cluster admin, edit, etc
- Assign a user to a keycloak group (e.g user-dev -> group: kube-dev). Such a mapping will allow in fact with the `id_token` returned as JWT from keycloak to get the group to which a user authenticated belongs:
  ```yaml
  ***REMOVED*** JWT Snippet from of the "user-admin" id_token
  "email": "user-admin@domain.com"
  "groups": [
    "kube-admin"
  ],
  ```

To play the scenario using kind + keycloak and configure them, execute the following script: `./scripts/kind-oidc-keycloak.sh`

***REMOVED******REMOVED*** Some useful References

- https://blogs.sap.com/2022/09/23/using-github-actions-openid-connect-in-kubernetes/
- https://dev.to/nuculabs_dev/kubernetes-openid-connect-integration-with-resource-owner-flow-ban
- https://kubernetes.io/docs/reference/access-authn-authz/authentication/***REMOVED***openid-connect-tokens
- https://access.redhat.com/documentation/en-us/red_hat_codeready_workspaces/2.7/html/administration_guide/managing-identities-and-authorizations_crw***REMOVED***obtaining-the-token-from-openshift-token-through-keycloak_crw
- https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect

Kind OIDC + Keycloak

- https://medium.com/@charled.breteche/kind-keycloak-securing-kubernetes-api-server-with-oidc-371c5faef902
- https://faun.pub/kubernetes-auth-e2f342a5f269
