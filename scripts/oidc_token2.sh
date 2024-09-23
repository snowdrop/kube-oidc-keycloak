CLIENT_ID="391f1c4c-fe45-4935-bcee-667b075a9962"
CLIENT_SECRET="TJPLoD4l3GaWdTx3PTbx1DlvvqG4dClG"
USERNAME="<kerberos_username>"
PASSWORD="<kerberos_password>"
TOKEN_URL="https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
INFO_URL="https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/userinfo"
OIDC_URL="https://sso.redhat.com/auth/realms/redhat-external"
SCOPE="openid"
OIDC_NAME="oidc_test"

OCP_API_SERVER="https://api-toolchain-host-operator.apps.stone-prd-host1.wdlc.p1.openshiftapps.com"

# Test: Getting the OIDC token using the clientId/secretId BUT we should look to the id_token !
# echo "curl -s -X POST $TOKEN_URL \
#         -H Content-Type: application/x-www-form-urlencoded \
#         -d grant_type=client_credentials \
#         -d client_id=$CLIENT_ID \
#         -d client_secret=$CLIENT_SECRET \
#         -d scope=$SCOPE"

response=$(curl -s -X POST "$TOKEN_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "scope=$SCOPE")

# Parse the response to get the access token
ACCESS_TOKEN=$(echo "$response" | jq -r '.access_token')
ID_TOKEN=$(echo "$response" | jq -r '.id_token')

#echo "Response: $(echo $response | jq -r .)"
echo "#### Access token decoded: $(jq -R 'split(".") | .[1] | @base64d | fromjson' <<< $ACCESS_TOKEN)"
echo "#### Id token decoded: $(jq -R 'split(".") | .[1] | @base64d | fromjson' <<< $ID_TOKEN)"

# response=$(curl -s -X POST "$TOKEN_URL" \
#   -H "Content-Type: application/x-www-form-urlencoded" \
#   -d "grant_type=client_credentials" \
#   -d "client_id=$CLIENT_ID" \
#   -d "client_secret=$CLIENT_SECRET" \
#   -d "scope=$SCOPE" \
#   -d response_type="refresh_token")
#
# # Trying to get a refresh token ..."
# echo "$response" | jq -r '.'

# Trying to set the credentials
kubectl config set-credentials $OIDC_NAME \
   --auth-provider=oidc \
   --auth-provider-arg=idp-issuer-url=$OIDC_URL \
   --auth-provider-arg=client-id=$CLIENT_ID \
   --auth-provider-arg=client-secret=$CLIENT_SECRET \
   --auth-provider-arg=id-token=$ID_TOKEN
   #--auth-provider-arg=refresh-token= \
   #--auth-provider-arg=idp-certificate-authority=( path to your ca certificate )

# Test 1: Get OIDC Token

# Response: {
  #  "error": "unauthorized_client",
  #  "error_description": "Client not allowed for direct access grants"
  #}

# response=$(curl -s -X POST "$TOKEN_URL" \
#   -H "Content-Type: application/x-www-form-urlencoded" \
#   -d "grant_type=password" \
#   -d "client_id=$CLIENT_ID" \
#   -d "client_secret=$CLIENT_SECRET" \
#   -d "username=$USERNAME" \
#   -d "password=$PASSWORD" \
#   -d "scope=$SCOPE")

# Test: Request OIDC Token using the Bearer Token
# response=$(curl -s -X POST "$TOKEN_URL" \
#   -H "Content-Type: application/x-www-form-urlencoded" \
#   -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
#   -d "client_id=$CLIENT_ID" \
#   -d "client_secret=$CLIENT_SECRET" \
#   -d "subject_token=$ACCESS_TOKEN" \
#   -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token")
#
# # Parse the response to extract the OIDC token
# echo "#### Response about request to get the OIDC token: "
# #echo $response | jq -r '.'
# OIDC_TOKEN=$(echo $response | jq -r '.access_token')
# echo "OIDC Token: $OIDC_TOKEN"
# echo "ID TOKEN decoded: $(jq -R 'split(".") | .[1] | @base64d | fromjson' <<< $ID_TOKEN)"
# Calling the API server
# echo "#### Response about request to get the OIDC token: "
# curl -H "Authorization: Bearer $ACCESS_TOKEN" $OCP_API_SERVER/api/accounts_mgmt/v1/current_account
