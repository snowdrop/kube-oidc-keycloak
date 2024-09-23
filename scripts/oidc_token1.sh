CLIENT_ID="391f1c4c-fe45-4935-bcee-667b075a9962"
CLIENT_SECRET="TJPLoD4l3GaWdTx3PTbx1DlvvqG4dClG"
AUTH_URL="https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/auth"
TOKEN_URL="https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
REDIRECT_URI="https://your-app.com/callback"
SCOPE="openid"
STATE="your-state-value"

# Step 1: Authorization Request
AUTH_REQUEST_URL="$AUTH_URL?client_id=$CLIENT_ID&response_type=code&scope=$SCOPE&state=$STATE"
echo "Authorize by visiting: $AUTH_REQUEST_URL"

# After user logs in and approves, you receive an authorization code...

# Step 2-4: Exchange Authorization Code for Tokens
AUTHORIZATION_CODE="your-authorization-code"

# Request tokens using curl
response=$(curl -s -X POST "$TOKEN_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&code=$AUTHORIZATION_CODE")

# Parse the response to extract the ID token
ID_TOKEN=$(echo "$response" | jq -r '.id_token')

echo "ID Token: $ID_TOKEN"


