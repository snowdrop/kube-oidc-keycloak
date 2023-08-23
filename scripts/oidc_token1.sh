***REMOVED***
***REMOVED***
AUTH_URL="https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/auth"
***REMOVED***
REDIRECT_URI="https://your-app.com/callback"
***REMOVED***
STATE="your-state-value"

***REMOVED*** Step 1: Authorization Request
AUTH_REQUEST_URL="$AUTH_URL?client_id=$CLIENT_ID&response_type=code&scope=$SCOPE&state=$STATE"
echo "Authorize by visiting: $AUTH_REQUEST_URL"

***REMOVED*** After user logs in and approves, you receive an authorization code...

***REMOVED*** Step 2-4: Exchange Authorization Code for Tokens
AUTHORIZATION_CODE="your-authorization-code"

***REMOVED*** Request tokens using curl
***REMOVED***
***REMOVED***
  -d "grant_type=authorization_code&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&code=$AUTHORIZATION_CODE")

***REMOVED*** Parse the response to extract the ID token
***REMOVED***

echo "ID Token: $ID_TOKEN"


