<?php

namespace SocialiteProviders\VKontakte;

use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\InvalidStateException;
use RuntimeException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    protected $fields = ['id', 'email', 'first_name', 'last_name', 'screen_name', 'photo_200'];

    public const IDENTIFIER = 'VKONTAKTE';

    protected $scopes = ['email'];

    protected $usesPKCE = true;

    /**
     * Last API version.
     */
    public const VERSION = '5.131';

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase('https://id.vk.ru/authorize', $state);
    }

    protected function getTokenUrl(): string
    {
        return 'https://id.vk.ru/oauth2/auth';
    }

    /**
     * {@inheritdoc}
     * @throws GuzzleException
     */
    protected function getUserByToken($token): array
    {
        $response = $this->getHttpClient()->post('https://id.vk.ru/oauth2/user_info', [
            RequestOptions::FORM_PARAMS => [
                'client_id'     => $this->clientId,
                'access_token'  => $token,
            ],
        ]);

        $response = json_decode((string) $response->getBody(), true);

        if (! is_array($response) || ! isset($response['user'])) {
            throw new RuntimeException(sprintf(
                'Invalid JSON response from VK: %s', $response
            ));
        }

        return $response['user'];
    }

    protected function getTokenHeaders($code): array
    {
        return [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ];
    }

    /**
     * {@inheritdoc}
     * @throws GuzzleException
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $this->parameters = array_merge($this->parameters, [
            'device_id' => $this->request->get('device_id'),
            'state' => Str::random(64),
        ]);

        $response = $this->getAccessTokenResponse($this->getCode());

        $user = $this->mapUserToObject($this->getUserByToken($response['access_token']));

        $this->credentialsResponseBody = $response;

        if ($user instanceof User) {
            $user->setAccessTokenResponseBody($this->credentialsResponseBody);
            $user->setRefreshToken($this->credentialsResponseBody['refresh_token']);
        }

        return $user->setToken($this->parseAccessToken($response))
            ->setExpiresIn($this->parseExpiresIn($response));
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'id'       => Arr::get($user, 'user_id'),
            'nickname' => Arr::get($user, 'screen_name'),
            'name'     => trim(Arr::get($user, 'first_name').' '.Arr::get($user, 'last_name')),
            'email'    => Arr::get($user, 'email'),
            'avatar'   => Arr::get($user, 'avatar'),
            'birthday' => Carbon::createFromFormat('d.m.Y', Arr::get($user, 'birthday')),
        ]);
    }

    /**
     * Set the user fields to request from Vkontakte.
     *
     * @param  array  $fields
     * @return $this
     */
    public function fields(array $fields)
    {
        $this->fields = $fields;

        return $this;
    }

    public static function additionalConfigKeys(): array
    {
        return ['lang'];
    }
}
