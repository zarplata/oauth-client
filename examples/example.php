<?php

$clientID = 'YOUR_CLIENT_ID';
$redirectURI = "https://your.domain/redirect_path";
$clientSecret = "YOUR_CLIENT_SECRET";

$client = new \ZpOauth\Client($clientID, $redirectURI, $clientSecret);

// User should follow THE link for sending authorization code to your application
// You can catch it on $redirectURI?code=AUTHORIZATION_CODE
$authorizeURL = $client->getAuthorizeURL();

$code = 'YOUR_AUTHORIZATION_CODE';
try {
    $authorizationPayload = $client->getAccessToken($code);
} catch (\Exception $e) {
    throw new Exception('authorization failed', 0 , $e);
}

//Header "Authorization: token $accessToken"
$accessToken = $authorizationPayload->getAccessToken();

//www.zarplata.ru user identifier
$zpUserID = $authorizationPayload->getUserID();
