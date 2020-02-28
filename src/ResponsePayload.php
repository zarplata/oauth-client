<?php


namespace ZpOAuth;


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
        $messagePattern = count($invalidPayloadFields) > 1 ? '%s fields are required' : '%s field is required';

        throw new InvalidPayloadException(
            sprintf($messagePattern, implode(", ", $invalidPayloadFields))
        );
    }
}
