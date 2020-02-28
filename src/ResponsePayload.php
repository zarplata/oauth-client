<?php


namespace ZpOauth;


use Psr\Http\Message\ResponseInterface;
use ZpOauth\Exceptions\InvalidPayloadException;

class ResponsePayload
{
    const REQUIRED_PAYLOAD_FIELDS = [
        'expires_in' => 'expiresIn',
        'access_token' => 'accessToken',
        'scope' => 'scope',
        'user_id' => 'userID',
        'refresh_token' => 'refreshToken',
    ];

    /** @var int */
    private $expiresIn;

    /** @var string */
    private $accessToken;

    /** @var string */
    private $scope;

    /** @var int */
    private $userID;

    /** @var string */
    private $refreshToken;

    /**
     * @param ResponseInterface $response
     * @return $this
     * @throws InvalidPayloadException
     */
    public function createFromResponse(ResponseInterface $response)
    {
        $payload = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
        $this->mapToPayload($payload);

        return $this;
    }

    /**
     * @return int
     */
    public function getExpiresIn()
    {
        return $this->expiresIn;
    }

    /**
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * @return string
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * @return int
     */
    public function getUserID()
    {
        return $this->userID;
    }

    /**
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @param array $payload
     * @throws InvalidPayloadException
     */
    private function mapToPayload(array $payload)
    {
        $invalidPayloadFields = [];
        foreach (static::REQUIRED_PAYLOAD_FIELDS as $requiredKey => $payloadField) {
            if (isset($payload[$requiredKey])) {
                $this->$payloadField = $payload[$requiredKey];
                continue;
            }

            $invalidPayloadFields[] = $requiredKey;
        }

        if (!$invalidPayloadFields) {
            return;
        }

        $messagePattern = count($invalidPayloadFields) > 1 ? '%s fields are required' : '%s field is required';

        throw new InvalidPayloadException(
            sprintf($messagePattern, implode(", ", $invalidPayloadFields))
        );
    }
}
