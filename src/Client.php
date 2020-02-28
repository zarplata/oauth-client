<?php

namespace ZpOAuth;

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\RequestOptions;
use ZpOauth\Exceptions\ForbiddenException;
use ZpOauth\Exceptions\UnauthorizedException;

class Client
{
    const BASE_URI = 'https://auth.zarplata.ru/v1/oauth';
    const DEFAULT_TIMEOUT = 1000;
    const HTTP_POST = 'POST';
    const DEFAULT_SCOPE = 'basic';
    const DEFAULT_GRANT_TYPE = 'authorization_code';
    const DEFAULT_RESPONSE_TYPE = 'code';

    /** @var string */
    private $responseType;

    /** @var int */
    private $clientID;

    /** @var string */
    private $redirectURI;

    /** @var string */
    private $scope;

    /** @var string */
    private $clientSecret;

    /** @var string */
    private $grantType;

    /** @var \GuzzleHttp\Client */
    private $httpClient;

    public function __construct($clientID, $redirectURI, $clientSecret)
    {
        $this->clientID = $clientID;
        $this->redirectURI = $redirectURI;
        $this->scope = self::DEFAULT_SCOPE;
        $this->clientSecret = $clientSecret;
        $this->grantType = self::DEFAULT_GRANT_TYPE;
        $this->responseType = self::DEFAULT_RESPONSE_TYPE;

        $this->httpClient = new \GuzzleHttp\Client([
            \GuzzleHttp\RequestOptions::HEADERS => [
                'User-Agent' => sprintf('ZpOAuthClient/%s', $this->redirectURI),
                'Content-Type' => 'application/json',
            ],
            'base_uri' => static::BASE_URI,
            \GuzzleHttp\RequestOptions::TIMEOUT => static::DEFAULT_TIMEOUT,
        ]);
    }

    public function getAuthorizeURL()
    {
        return sprintf(
            '%s/authorize?response_type=%s&client_id=%d&redirect_uri=%s&scope=%s',
            static::BASE_URI,
            $this->responseType,
            $this->clientID,
            $this->redirectURI,
            $this->scope
        );
    }

    /**
     * @param $code
     * @return ResponsePayload
     * @throws ForbiddenException
     * @throws UnauthorizedException
     * @throws \ZpOauth\Exceptions\ClientException
     * @throws \ZpOauth\Exceptions\InvalidPayloadException
     */
    public function getAccessToken($code)
    {
        try {
            $response = $this->httpClient->post(
                sprintf('%s/access_token', static::BASE_URI),
                [
                    RequestOptions::BODY => \GuzzleHttp\json_encode(
                        [
                            'client_id' => $this->clientID,
                            'client_secret' => $this->clientSecret,
                            'scope' => $this->scope,
                            'grant_type' => $this->grantType,
                            'code' => $code,
                            'redirect_uri' => $this->redirectURI,
                        ]
                    ),
                ]
            );
        } catch (ClientException $e) {
            $response = $e->getResponse();
            $decodedResponse = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
            $message = isset($decodedResponse['errors']['message']) ? $decodedResponse['errors']['message'] : null;

            switch (true) {
                case $response->getStatusCode() === Response::HTTP_UNAUTHORIZED && $message:
                    throw new UnauthorizedException($message);
                case $response->getStatusCode() === Response::HTTP_FORBIDDEN && $message:
                    throw new ForbiddenException($message);
                default:
                    throw new \ZpOauth\Exceptions\ClientException(
                        'unable to perform authorization request',
                        \ZpOauth\Exceptions\ClientException::ERROR_CODE,
                        $e
                    );
            }
        } catch (RequestException $e) {
            throw new \ZpOauth\Exceptions\ClientException(
                'unable to perform authorization request',
                \ZpOauth\Exceptions\ClientException::ERROR_CODE,
                $e
            );
        }

        return (new ResponsePayload())->createFromResponse($response);
    }
}
