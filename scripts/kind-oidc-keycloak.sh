set -e

KEYCLOAK_HOSTNAME=keycloak.127.0.0.1.nip.io
TEMP_SSL_DIR=".ssl"
CLUSTER_NAME="kind"

echo "***REMOVED*** do some clean up"
rm -rf ${TEMP_SSL_DIR}
rm -rf .terraform
rm -rf {.*.hcl,*.hcl,*.tf,*.tf.bak,*.sh.bak,kube-config-credentials.sh,terraform.*}

echo "***REMOVED*** create a folder to store certificates"
mkdir -p ${TEMP_SSL_DIR}

echo "***REMOVED*** generate an rsa key"
openssl genrsa -out .ssl/root-ca-key.pem 2048

echo "***REMOVED*** generate root certificate"
openssl req -x509 -new -nodes -key .ssl/root-ca-key.pem \
  -days 3650 -sha256 -out .ssl/root-ca.pem -subj "/CN=kube-ca"

if kind get clusters | grep -q "$CLUSTER_NAME"; then
  echo "Kind cluster $CLUSTER_NAME exists. Deleting..."

  ***REMOVED*** Delete the kind cluster
  kind delete cluster --name "$CLUSTER_NAME"

  echo "Kind cluster $CLUSTER_NAME deleted."
fi

kind create cluster --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "127.0.0.1"
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
        authorization-mode: "AlwaysAllow"

    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        oidc-client-id: kube
        oidc-issuer-url: https://$KEYCLOAK_HOSTNAME/realms/master
        oidc-username-claim: email
        oidc-groups-claim: groups
        oidc-ca-file: /etc/ca-certificates/keycloak/root-ca.pem
  extraMounts:
  - hostPath: $PWD/.ssl/root-ca.pem
    containerPath: /etc/ca-certificates/keycloak/root-ca.pem
    readOnly: true
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
    listenAddress: "0.0.0.0"
  - containerPort: 443
    hostPort: 443
    protocol: TCP
    listenAddress: "0.0.0.0"
EOF

echo "***REMOVED*** Create a kubernetes secret containing the Root CA certificate and its key"
kubectl create ns keycloak
kubectl create secret tls -n keycloak ca-key-pair \
  --cert=.ssl/root-ca.pem \
  --key=.ssl/root-ca-key.pem

echo "***REMOVED*** Install ingress controller"
helm upgrade --install ingress-nginx ingress-nginx \
   --repo https://kubernetes.github.io/ingress-nginx \
   -n ingress --create-namespace \
   --set controller.service.type=NodePort \
   --set controller.hostPort.enabled=true \
   --set controller.watchIngressWithoutClass=true

echo "***REMOVED*** Deploy the certificate manager"
helm repo add jetstack https://charts.jetstack.io
helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true

echo "***REMOVED*** Create an Issuer where you specify the secret: ca-key-pair"
kubectl delete issuer/ca-issuer -n keycloak | true
cat <<EOF | kubectl apply -f -
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ca-issuer
  namespace: keycloak
spec:
  ca:
    secretName: ca-key-pair
EOF

echo "***REMOVED*** Install and configure keycloak"
helm upgrade --install --wait --timeout 15m \
  --namespace keycloak --create-namespace \
  --repo https://charts.bitnami.com/bitnami keycloak keycloak \
  --reuse-values --values - <<EOF
auth:
  createAdminUser: true
  adminUser: admin
  adminPassword: admin
  managementUser: manager
  managementPassword: manager
proxy: edge ***REMOVED*** Needed to avoid https -> http redirect
ingress:
  enabled: true
  annotations:
    cert-manager.io/issuer: ca-issuer
  hostname: ${KEYCLOAK_HOSTNAME}
  ingressClassName: nginx
  tls: true
  extraTls:
  - hosts:
    - ${KEYCLOAK_HOSTNAME}
postgresql:
  enabled: true
  auth:
   username: admin
   password: admin
EOF

echo "Creating the keycloak terraform config file"
cat <<'EOF' > keycloak.tf
terraform {
  required_providers {
    keycloak = {
      source  = "mrparkers/keycloak"
      version = ">=4.0.0"
    }
  }
}
***REMOVED*** configure keycloak provider
provider "keycloak" {
  client_id                = "admin-cli"
  username                 = "admin"
  password                 = "admin"
  url                      = "https://KEYCLOAK_HOSTNAME"
  tls_insecure_skip_verify = true
}
locals {
  realm_id = "master"
  groups   = ["kube-dev", "kube-admin"]
  user_groups = {
    user-dev   = ["kube-dev"]
    user-admin = ["kube-admin"]
  }
}
***REMOVED*** create groups
resource "keycloak_group" "groups" {
  for_each = toset(local.groups)
  realm_id = local.realm_id
  name     = each.key
}
***REMOVED*** create users
resource "keycloak_user" "users" {
  for_each       = local.user_groups
  realm_id       = local.realm_id
  username       = each.key
  enabled        = true
  email          = "${each.key}@domain.com"
  email_verified = true
  first_name     = each.key
  last_name      = each.key
  initial_password {
    value = each.key
  }
}
***REMOVED*** configure use groups membership
resource "keycloak_user_groups" "user_groups" {
  for_each  = local.user_groups
  realm_id  = local.realm_id
  user_id   = keycloak_user.users[each.key].id
  group_ids = [for g in each.value : keycloak_group.groups[g].id]
}
***REMOVED*** create groups openid client scope
resource "keycloak_openid_client_scope" "groups" {
  realm_id               = local.realm_id
  name                   = "groups"
  include_in_token_scope = true
  gui_order              = 1
}
resource "keycloak_openid_group_membership_protocol_mapper" "groups" {
  realm_id        = local.realm_id
  client_scope_id = keycloak_openid_client_scope.groups.id
  name            = "groups"
  claim_name      = "groups"
  full_path       = false
}
***REMOVED*** create kube openid client
resource "keycloak_openid_client" "kube" {
  realm_id                     = local.realm_id
  client_id                    = "kube"
  name                         = "kube"
  enabled                      = true
  access_type                  = "CONFIDENTIAL"
  client_secret                = "kube-client-secret"
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = true
}
***REMOVED*** configure kube openid client default scopes
resource "keycloak_openid_client_default_scopes" "kube" {
  realm_id  = local.realm_id
  client_id = keycloak_openid_client.kube.id
  default_scopes = [
    "email",
    keycloak_openid_client_scope.groups.name,
  ]
}
EOF
sed -i.bak "s/KEYCLOAK_HOSTNAME/$KEYCLOAK_HOSTNAME/g" keycloak.tf

echo "***REMOVED*** Apply the terraform config"
terraform init && terraform apply -auto-approve

echo "***REMOVED*** Create 2 ClusterRole; one for the group: kube-admin and a second for kube-dev having different RBAC: Cluster and edit"
kubectl apply -f - <<EOF
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: kube-admin
subjects:
- kind: Group
  name: kube-admin
  apiGroup: rbac.authorization.k8s.io
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: kube-dev
subjects:
- kind: Group
  name: kube-dev
  apiGroup: rbac.authorization.k8s.io
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
EOF

echo "***REMOVED*** Get the keycloak tls certificate from the secret created by the certificate manager"
NAMESPACE=${NAMESPACE:=keycloak}
SECRET_NAME=${SECRET_NAME:=keycloak.127.0.0.1.nip.io-tls}
CA_FILE=${CA_FILE:=tls.crt}

kubectl get secret/${SECRET_NAME} -n ${NAMESPACE} -o json | jq -r --arg CERT_NAME "$CA_FILE" '.data[$CERT_NAME] | @base64d' > ${TEMP_SSL_DIR}/${CA_FILE}
kubectl get secret/${SECRET_NAME} -n ${NAMESPACE} -o json | jq -r --arg CERT_NAME "$CA_FILE" '.data[$CERT_NAME] | @base64d' | openssl x509 -noout -text > ${TEMP_SSL_DIR}/${CA_FILE}.txt

echo "***REMOVED*** Create a bash script able to set the kube config OIDC credentials for a user"
cat <<'EOF' > kube-config-credentials.sh
ISSUER=https://KEYCLOAK_HOSTNAME/realms/master
ENDPOINT=$ISSUER/protocol/openid-connect/token
CA_DATA=$(cat .ssl/tls.crt | base64 | tr -d '\n')

ID_TOKEN=$(curl -k -s -X POST $ENDPOINT \
  -d grant_type=password \
  -d client_id=kube \
  -d client_secret=kube-client-secret \
  -d username=$1 \
  -d password=$1 \
  -d scope=openid \
  -d response_type=id_token | jq -r '.id_token')

REFRESH_TOKEN=$(curl -k -s -X POST $ENDPOINT \
  -d grant_type=password \
  -d client_id=kube \
  -d client_secret=kube-client-secret \
  -d username=$1 \
  -d password=$1 \
  -d scope=openid \
  -d response_type=id_token | jq -r '.refresh_token')

kubectl config set-credentials $1 \
  --auth-provider=oidc \
  --auth-provider-arg=client-id=kube \
  --auth-provider-arg=client-secret=kube-client-secret \
  --auth-provider-arg=idp-issuer-url=$ISSUER \
  --auth-provider-arg=id-token=$ID_TOKEN \
  --auth-provider-arg=refresh-token=$REFRESH_TOKEN \
  --auth-provider-arg=idp-certificate-authority-data=$CA_DATA

kubectl config set-context $1 --cluster=kind-kind --user=$1
EOF
sed -i.bak "s/KEYCLOAK_HOSTNAME/$KEYCLOAK_HOSTNAME/g" kube-config-credentials.sh
chmod +x kube-config-credentials.sh

echo "***REMOVED*** Configure within the kubectl config for a user the OIDC auth_provider"
./kube-config-credentials.sh user-admin
./kube-config-credentials.sh user-dev

echo "***REMOVED*** Test it"
kubectl config use-context user-dev
kubectl create ns test | true

kubectl config use-context user-admin
kubectl create ns test