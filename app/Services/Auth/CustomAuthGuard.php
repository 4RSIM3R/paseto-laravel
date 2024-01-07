<?php

namespace App\Services\Auth;

use DateInterval;
use DateTime;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Exception\InvalidKeyException;
use ParagonIE\Paseto\Exception\InvalidPurposeException;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Exception\SecurityException;
use ParagonIE\Paseto\JsonToken;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Protocol\Version1;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\Purpose;

class CustomAuthGuard implements Guard
{

    use GuardHelpers, Macroable {
        __call as macroCall;
    }

    protected SymmetricKey $key;
    protected Request $request;

    /**
     * @param UserProvider $provider
     */
    public function __construct(UserProvider $provider, Request $request)
    {
        $this->setProvider($provider);
        $this->key = SymmetricKey::fromEncodedString(base64_encode("SECRET"), new Version1);
        $this->request = $request;
    }


    public function check()
    {
        // TODO: Implement check() method.
    }

    public function guest()
    {
        // TODO: Implement guest() method.
    }

    /**
     * @throws InvalidPurposeException
     * @throws InvalidKeyException
     * @throws PasetoException
     */
    public function attempt(array $credentials = []): bool|string
    {
        $this->user = $this->provider->retrieveByCredentials($credentials);
        $this->user = $this->user && $this->provider->validateCredentials($this->user, $credentials) ? $this->user : null;

        if ($this->user) {
            return $this->login($this->user);
        }

        return false;
    }

    /**
     * @throws InvalidPurposeException
     * @throws PasetoException
     * @throws InvalidKeyException
     */
    private function login($user): string
    {
        $token = (new Builder())
            ->setKey($this->key)
            ->setVersion(new Version1)
            ->setPurpose(Purpose::local())
            ->setIssuedAt()
            ->setNotBefore()
            ->setExpiration((new DateTime())->add(new DateInterval('P01D')))
            ->setClaims([
                'id' => $user->id,
                'email' => $user->email,
            ])->toString();
        return str_replace("v1.local.", "", $token);
    }

    /**
     * @throws SecurityException
     * @throws InvalidVersionException
     * @throws PasetoException
     */
    public function user(): ?Authenticatable
    {
        if ($this->hasUser() && !app()->runningUnitTests()) {
            return $this->user;
        }

        $decoded = $this->getTokenPayload();

        if (!$decoded) {
            return null;
        }

        $this->user = $this->getProvider()->retrieveById($decoded->getClaims()['id']);

        return $this->user;
    }

    /**
     * @throws SecurityException
     * @throws InvalidVersionException
     * @throws PasetoException
     */
    public function getTokenPayload(): ?JsonToken
    {
        $token = $this->request->bearerToken();
        if ($token) {
            $parser = Parser::getLocal($this->key, ProtocolCollection::v1());
            return $parser->parse($token);
        }
        return null;
    }

    public function id()
    {
        // TODO: Implement id() method.
    }

    /**
     * @throws InvalidPurposeException
     * @throws PasetoException
     * @throws InvalidKeyException
     */
    public function validate(array $credentials = []): bool|string
    {
        return $this->attempt($credentials);
    }

    public function hasUser()
    {
        // TODO: Implement hasUser() method.
    }

}
