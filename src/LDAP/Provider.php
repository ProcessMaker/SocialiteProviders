<?php

namespace SocialiteProviders\LDAP;

use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use ProcessMaker\Models\Setting;

class Provider extends AbstractProvider
{
    const IDENTIFIER = 'LDAP';

    protected $errorMessage = '';

    /**
     * Get the authentication URL for the provider.
     * 
     * @param string $state
     * @return string
     */
    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase('', $state);
    }

    /**
     * Get the token URL for the provider.
     * 
     * @return string
     */
    protected function getTokenUrl(): string
    {
        return '';
    }

    /**
     * Get the raw user for the given access token.
     * 
     * @param string $token
     * @return array
     */
    protected function getUserByToken($token): array
    {
        return [];
    }

    /**
     * Map the raw user array to a Socialite User instance.
     * 
     * @param array $user
     * @return \Laravel\Socialite\Two\User
     */
    protected function mapUserToObject(array $user): \Laravel\Socialite\Two\User
    {
        return null;
    }

    /**
     * Obtains the fixed parameters required by Socialite. This method is for internal use, 
     * and its content affects the behavior of the Socialite.
     * @return array
     */
    public static function additionalConfigKeys()
    {
        return [
            'client_id',
            'client_secret',
            'redirect'
        ];
    }

    /**
     * This method implements the redirection to the authentication provider, but 
     * since LDAP is part of the ProcessMaker service, it remains blank.
     * @return string
     */
    public function redirect()
    {
        return '';
    }

    /**
     * Retrieve LDAP configuration values.
     * 
     * @return array
     */
    protected function getLDAPSettings()
    {
        $query = Setting::query();
        $collection = $query->where('group', 'LDAP')
            ->get();
        $result = [];
        foreach ($collection as $value) {
            $result[$value->key] = $value->config;
        }
        return $result;
    }

    /**
     * Get the last error message.
     * 
     * @return string
     */
    public function getErrorMessage()
    {
        return $this->errorMessage;
    }

    /**
     * Obtain the connection to the LDAP service.
     * 
     * @param array $setting
     * @return \LdapRecord\Connection
     */
    protected function getLDAPConnection($setting)
    {
        $connection = new \LdapRecord\Connection([
            'hosts' => [$setting['services.ldap.server.address']],
            'port' => $setting['services.ldap.server.port'],
            'use_ssl' => false,
            'use_tls' => $setting['services.ldap.server.tls'],
            'username' => $setting['services.ldap.authentication.username'],
            'password' => $setting['services.ldap.authentication.password'],
            'timeout' => 5,
            'base_dn' => $setting['services.ldap.base_dn'],
            'follow_referrals' => false,
            'version' => 3,
            'options' => [],
        ]);

        try {
            $connection->connect();
        } catch (\LdapRecord\Auth\BindException $e) {
            $error = $e->getDetailedError()->getDiagnosticMessage();
            if (strpos($error, '532') !== false) {
                $this->errorMessage = 'Your password has expired.';
            } elseif (strpos($error, '533') !== false) {
                $this->errorMessage = 'Your account is disabled.';
            } elseif (strpos($error, '701') !== false) {
                $this->errorMessage = 'Your account has expired';
            } elseif (strpos($error, '775') !== false) {
                $this->errorMessage = 'Your account is locked.';
            }
            $this->errorMessage = 'Username or password is incorrect.';
        }
        return $connection;
    }

    /**
     * Authenticate a user against Active Directory, returning true if the user has 
     * the correct parameters and false otherwise.
     * 
     * @param ProcessMaker\Models\User $user
     * @param string $password
     * @return bool
     */
    public function auth($user, $password)
    {
        $setting = $this->getLDAPSettings();

        if (!(is_array($setting) && !empty($setting))) {
            $this->errorMessage = 'The LDAP configuration values do not exist or have not been set.';
            return false;
        }
        if (!isset($setting['services.ldap.enabled'])) {
            $this->errorMessage = '"The configuration services.ldap.enabled does not exist."';
            return false;
        }
        if ($setting['services.ldap.enabled'] === false) {
            $this->errorMessage = 'The configuration is disabled services.ldap.enabled is false.';
            return false;
        }

        $identifier = $setting['services.ldap.identifiers.user'] ?? 'samaccountname';

        $connection = $this->getLDAPConnection($setting);

        $username = $user->username;
        $query = $connection->query();
        $results = $query
            ->where($identifier, '=', $username)
            ->select(['cn', $identifier, 'userPassword'])
            ->get();

        if (count($results) <= 0) {
            $this->errorMessage = 'The user was not found.';
            return false;
        }

        $entry = $query->first();
        $sw = isset($entry['userpassword']) && isset($entry['userpassword'][0]);
        $userPassword = $sw ? $entry['userpassword'][0] : '';

        if ($password !== $userPassword) {
            $this->errorMessage = 'The password is incorrect.';
            return false;
        }

        session()->put('ldap-auth-user', $entry);
        $this->errorMessage = 'The user has permissions and the password is correct.';
        return true;
    }

    /**
     * This returns the authenticated username according to the identifier configured 
     * in the LDAP tab.
     * 
     * @return \stdClass
     */
    public function user()
    {
        $setting = $this->getLDAPSettings();
        $identifier = $setting['services.ldap.identifiers.user'] ?? 'samaccountname';

        $user = session()->get('ldap-auth-user');
        $sw = isset($user[$identifier]) && isset($user[$identifier][0]);
        $obj = new \stdClass;
        $obj->id = ''; //this only for compatibility
        $obj->username = $sw ? $user[$identifier][0] : '';
        return $obj;
    }
}
