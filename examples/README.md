# Example implementations

These different examples use the `slim/slim ^4.5` framework.

## Installation

0. Run `composer install` in this directory to install dependencies
0. Create a private key `openssl genrsa -out private.key 2048`
0. Create a public key `openssl rsa -in private.key -pubout -out public.key`
0. Start a PHP server `php -S localhost:8000 -t public`

## Issuing a new access token and refresh token from credentials

Use the following cURL command:

```
curl -X "POST" "http://localhost:8000/access_token.php/access_token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     --data-urlencode "username=admin" \
     --data-urlencode "password=pass"
```

## Testing access to the API with the access token

Use the following cURL command. Replace `{{ACCESS_TOKEN}}` with an access token from another request:

```
curl -X "GET" "http://localhost:8000/api.php/test" \
     -H "Authorization: Bearer {{ACCESS_TOKEN}}"
```

## Issuing a new access token with the refresh token

Use the following cURL command. Replace `{{REFRESH_TOKEN}}` with a refresh token from another request:

```
curl -X "POST" "http://localhost:8000/access_token.php/access_token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     --data-urlencode "refresh_token={{REFRESH_TOKEN}}"
```
