***REMOVED***
***REMOVED***
USERNAME="***REMOVED***"
PASSWORD="***REMOVED***"
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***

***REMOVED***

***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***

***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***

***REMOVED***
***REMOVED***
***REMOVED***

***REMOVED***
***REMOVED***
***REMOVED***

***REMOVED*** ***REMOVED***
***REMOVED*** ***REMOVED***
***REMOVED*** ***REMOVED***
***REMOVED*** ***REMOVED***
***REMOVED*** ***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED*** ***REMOVED*** Trying to get a refresh token ..."
***REMOVED*** echo "$response" | jq -r '.'

***REMOVED*** Trying to set the credentials
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
   ***REMOVED***--auth-provider-arg=refresh-token= \
   ***REMOVED***--auth-provider-arg=idp-certificate-authority=( path to your ca certificate )

***REMOVED*** Test 1: Get OIDC Token

***REMOVED*** Response: {
  ***REMOVED***  "error": "unauthorized_client",
  ***REMOVED***  "error_description": "Client not allowed for direct access grants"
  ***REMOVED***}

***REMOVED*** ***REMOVED***
***REMOVED*** ***REMOVED***
***REMOVED***   -d "grant_type=password" \
***REMOVED*** ***REMOVED***
***REMOVED*** ***REMOVED***
***REMOVED***   -d "username=$USERNAME" \
***REMOVED***   -d "password=$PASSWORD" \
***REMOVED*** ***REMOVED***

***REMOVED*** Test: Request OIDC Token using the Bearer Token
***REMOVED*** ***REMOVED***
***REMOVED*** ***REMOVED***
***REMOVED***   -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
***REMOVED*** ***REMOVED***
***REMOVED*** ***REMOVED***
***REMOVED***   -d "subject_token=$ACCESS_TOKEN" \
***REMOVED***   -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token")
***REMOVED***
***REMOVED*** ***REMOVED*** Parse the response to extract the OIDC token
***REMOVED*** echo "***REMOVED******REMOVED******REMOVED******REMOVED*** Response about request to get the OIDC token: "
***REMOVED*** ***REMOVED***echo $response | jq -r '.'
***REMOVED*** OIDC_TOKEN=$(echo $response | jq -r '.access_token')
***REMOVED*** echo "OIDC Token: $OIDC_TOKEN"
***REMOVED*** echo "ID TOKEN decoded: $(jq -R 'split(".") | .[1] | @base64d | fromjson' <<< $ID_TOKEN)"
***REMOVED*** Calling the API server
***REMOVED*** echo "***REMOVED******REMOVED******REMOVED******REMOVED*** Response about request to get the OIDC token: "
***REMOVED*** curl -H "Authorization: Bearer $ACCESS_TOKEN" $OCP_API_SERVER/api/accounts_mgmt/v1/current_account