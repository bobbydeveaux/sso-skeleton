<?php

namespace DVO\OAuth2;

use OAuth2\IOAuth2GrantCode;
use OAuth2\IOAuth2GrantUser;
use OAuth2\IOAuth2RefreshTokens;
use OAuth2\Model\IOAuth2Client;
use OAuth2\Model\OAuth2Client;
use OAuth2\Model\OAuth2AuthCode;

/**
 * PDO storage engine for the OAuth2 Library.
 */
class OAuth2StoragePdo implements IOAuth2GrantCode, IOAuth2GrantUser, IOAuth2RefreshTokens
{
    /**
     * Centralized table names
     *
     * @var string
     */
    const TABLE_CLIENTS = 'sso_clients';
    const TABLE_CODES   = 'sso_auth_codes';
    const TABLE_TOKENS  = 'sso_access_tokens';
    const TABLE_REFRESH = 'sso_refresh_tokens';
    const TABLE_USERS   = 'sso_users';
    /**@#-*/

    /**
     * @var PDO
     */
    private $db;

    /**
     * @var string
     */
    private $salt;

    /**
     * Implements OAuth2::__construct().
     */
    public function __construct(\PDO $db, $salt = 'Dv0m3d14!')
    {
        $this->db   = $db;
        $this->salt = $salt;
    }

    /**
     * Handle PDO exceptional cases.
     */
    private function handleException($e)
    {
        throw $e;
    }

    /**
     * Little helper function to add a new client to the database.
     *
     *
     * @param string $clientId     Client identifier to be stored.
     * @param string $clientSecret Client secret to be stored.
     * @param string $redirectUri  Redirect URI to be stored.
     */
    public function addClient($clientId, $clientSecret, $redirectUri)
    {
        try {
            $options = [
                'cost' => 11,
                'salt' => mcrypt_create_iv(22, MCRYPT_DEV_URANDOM),
            ];

            // username and password is username / password
            $clientSecret = password_hash($clientSecret, PASSWORD_BCRYPT, $options);

            $sql = 'INSERT INTO '.self::TABLE_CLIENTS.' (client_id, client_secret, redirect_uri)
                    VALUES (:client_id, :client_secret, :redirect_uri)';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':client_id', $clientId, \PDO::PARAM_STR);
            $stmt->bindParam(':client_secret', $clientSecret, \PDO::PARAM_STR);
            $stmt->bindParam(':redirect_uri', $redirectUri, \PDO::PARAM_STR);
            $stmt->execute();
        } catch (\PDOException $e) {
            $this->handleException($e);
        }

        return true;
    }

    /**
     * Implements IOAuth2Storage::checkClientCredentials().
     *
     */
    public function checkClientCredentials(IOAuth2Client $clientId, $clientSecret = null)
    {
        try {
            $clientId = $clientId->getPublicId();
            $sql = 'SELECT client_secret FROM '.self::TABLE_CLIENTS.' WHERE client_id = :client_id';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':client_id', $clientId, \PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($clientSecret === null) {
                return $result !== false;
            }

            return $this->checkPassword($clientSecret, $result['client_secret'], $clientId);
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::getRedirectUri().
     */
    public function getClientDetails($clientId)
    {
        try {
            $sql = 'SELECT redirect_uri FROM '.self::TABLE_CLIENTS.' WHERE client_id = :client_id';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':client_id', $clientId, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($result === false) {
                return false;
            }

            return isset($result['redirect_uri']) && $result['redirect_uri'] ? $result : null;
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::getAccessToken().
     */
    public function getAccessToken($oauth_token)
    {
        return $this->getToken($oauth_token, false);
    }

    /**
     * Implements IOAuth2Storage::setAccessToken().
     */
    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null)
    {
        $this->setToken($oauth_token, $client_id, $user_id, $expires, $scope, false);
    }

    /**
     * @see IOAuth2Storage::getRefreshToken()
     */
    public function getRefreshToken($refreshToken)
    {
        return $this->getToken($refreshToken, true);
    }

    /**
     * @see IOAuth2Storage::setRefreshToken()
     */
    public function setRefreshToken($refreshToken, $clientId, $userId, $expires, $scope = null)
    {
        return $this->setToken($refreshToken, $clientId, $userId, $expires, $scope, true);
    }

    /**
     * @see IOAuth2Storage::unsetRefreshToken()
     */
    public function unsetRefreshToken($refreshToken)
    {
        try {
            $sql = 'DELETE FROM '.self::TABLE_TOKENS.' WHERE refresh_token = :refresh_token';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':refresh_token', $refreshToken, PDO::PARAM_STR);
            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::getAuthCode().
     */
    public function getAuthCode($code)
    {
        try {
            $sql = 'SELECT code, client_id, user_id, redirect_uri, expires, scope
                    FROM '.self::TABLE_CODES.' auth_codes WHERE code = :code';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':code', $code, \PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($result !== false) {
                $authCode = new OAuth2AuthCode(
                    $result['client_id'],
                    $result['code'],
                    $result['expires'],
                    $result['scope'],
                    $result['user_id'],
                    $result['redirect_uri']
                );

                return $authCode;
            }

            return null;
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::setAuthCode().
     */
    public function setAuthCode($code, $clientId, $userId, $redirectUri, $expires, $scope = null)
    {
        try {
            $sql = 'INSERT INTO '.self::TABLE_CODES.' (code, client_id, user_id, redirect_uri, expires, scope)
                    VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope)';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':code', $code, PDO::PARAM_STR);
            $stmt->bindParam(':client_id', $clientId, PDO::PARAM_STR);
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_STR);
            $stmt->bindParam(':redirect_uri', $redirectUri, PDO::PARAM_STR);
            $stmt->bindParam(':expires', $expires, PDO::PARAM_INT);
            $stmt->bindParam(':scope', $scope, PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * @see IOAuth2Storage::checkRestrictedGrantType()
     */
    public function checkRestrictedGrantType(IOAuth2Client $client, $grantType)
    {
        return true; // Not implemented
    }

    /**
     * Creates a refresh or access token
     *
     * @param string $token     Access or refresh token id
     * @param string $clientId
     * @param mixed  $userId
     * @param int    $expires
     * @param string $scope
     * @param bool   $isRefresh
     */
    protected function setToken($token, $clientId, $userId, $expires, $scope, $isRefresh = true)
    {
        try {
            $tableName = $isRefresh ? self::TABLE_REFRESH :  self::TABLE_TOKENS;

            $sql = "INSERT INTO $tableName (oauth_token, client_id, user_id, expires, scope)
                    VALUES (:token, :client_id, :user_id, :expires, :scope)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':token', $token, PDO::PARAM_STR);
            $stmt->bindParam(':client_id', $clientId, PDO::PARAM_STR);
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_STR);
            $stmt->bindParam(':expires', $expires, PDO::PARAM_INT);
            $stmt->bindParam(':scope', $scope, PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Retrieves an access or refresh token.
     *
     * @param string $token
     * @param bool   $isRefresh
     *
     * @return array|null
     */
    protected function getToken($token, $isRefresh = true)
    {
        try {
            $tableName = $isRefresh ? self::TABLE_REFRESH :  self::TABLE_TOKENS;
            $tokenName = $isRefresh ? 'refresh_token' : 'oauth_token';

            $sql = "SELECT oauth_token AS $tokenName, client_id, expires, scope, user_id
                    FROM $tableName
                    WHERE oauth_token = :token";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':token', $token, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            return $result !== false ? $result : null;
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Change/override this to whatever your own password hashing method is.
     *
     * @param  string $clientSecret
     * @param  string $clientId
     *
     * @return string
     */
    protected function hash($clientSecret, $clientId)
    {
        return hash('sha1', $clientId.$clientSecret.$this->salt);
    }

    /**
     * Checks the password.
     * Override this if you need to
     *
     * @param string $try
     * @param string $clientSecret
     * @param string $clientId
     *
     * @return bool
     */
    protected function checkPassword($try, $clientSecret, $clientId)
    {
      if (false === password_verify($try, $clientSecret)) {
          return false;
      }

      return true;
    }

    /**
     * Take the provided authorization code values and store them somewhere.
     *
     * This function should be the storage counterpart to getAuthCode().
     * If storage fails for some reason, we're not currently checking for any sort of success/failure, so you should
     * bail out of the script and provide a descriptive fail message.
     * Required for OAuth2::GRANT_TYPE_AUTH_CODE.
     *
     * @param string        $code        Authorization code string to be stored.
     * @param IOAuth2Client $client      The client associated with this authorization code.
     * @param mixed         $data        Application data to associate with this authorization code.
     * @param string        $redirectUri Redirect URI to be stored.
     * @param int           $expires     The timestamp when the authorization code will expire.
     * @param string        $scope       l(optional) Scopes to be stored in space-separated string.
     *
     * @ingroup oauth2_section_4
     */
    public function createAuthCode($code, IOAuth2Client $client, $data, $redirectUri, $expires, $scope = null)
    {
        try {
            $clientId = $client->getPublicId();
            $sql = "INSERT INTO " . self::TABLE_CODES . " (code,
                                                        client_id,
                                                        user_id,
                                                        redirect_uri,
                                                        expires,
                                                        scope)
                    VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':code', $code, \PDO::PARAM_STR);
            $stmt->bindParam(':client_id', $clientId, \PDO::PARAM_STR);
            $stmt->bindParam(':user_id', $data, \PDO::PARAM_STR);
            $stmt->bindParam(':redirect_uri', $redirectUri, \PDO::PARAM_STR);
            $stmt->bindParam(':expires', $expires, \PDO::PARAM_INT);
            $stmt->bindParam(':scope', $scope, \PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Marks auth code as expired.
     *
     * Depending on implementation it can change expiration date on auth code or remove it at all.
     *
     * @param string $code
     */
    public function markAuthCodeAsUsed($code)
    {

    }

    /**
     * Get a client by its ID.
     *
     * @param string $clientId
     *
     * @return IOAuth2Client
     */
    public function getClient($clientId)
    {
        $sql = 'SELECT client_id, client_secret, redirect_uri
                FROM '.self::TABLE_CLIENTS.'
                WHERE client_id = :client_id';
        $stmt = $this->db->prepare($sql);
        $stmt->bindParam(':client_id', $clientId, \PDO::PARAM_STR);
        $stmt->execute();

        $result = $stmt->fetch(\PDO::FETCH_ASSOC);

        return new OAuth2Client($result['client_id'], $result['client_secret'], array($result['redirect_uri']));
    }

    /**
     * Store the supplied access token values to storage.
     *
     * We need to store access token data as we create and verify tokens.
     *
     * @param string        $oauthToken The access token string to be stored.
     * @param IOAuth2Client $client     The client associated with this refresh token.
     * @param mixed         $data       Application data associated with the refresh token, such as a User object.
     * @param int           $expires    The timestamp when the refresh token will expire.
     * @param string        $scope      (optional) Scopes to be stored in space-separated string.
     *
     * @ingroup oauth2_section_4
     */
    public function createAccessToken($oauthToken, IOAuth2Client $client, $data, $expires, $scope = null)
    {
        try {
            $clientId = $client->getPublicId();

            $sql = "INSERT INTO " . self::TABLE_TOKENS . " (oauth_token,
                                                            client_id,
                                                            user_id,
                                                            expires,
                                                            scope)
                    VALUES (:oauth_token, :client_id, :user_id, :expires, :scope)";

            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':oauth_token', $oauthToken, \PDO::PARAM_STR);
            $stmt->bindParam(':client_id', $clientId, \PDO::PARAM_STR);
            $stmt->bindParam(':user_id', $data, \PDO::PARAM_STR);
            $stmt->bindParam(':expires', $expires, \PDO::PARAM_INT);
            $stmt->bindParam(':scope', $scope, \PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

     /**
     * Take the provided refresh token values and store them somewhere.
     *
     * This function should be the storage counterpart to getRefreshToken().
     * If storage fails for some reason, we're not currently checking for
     * any sort of success/failure, so you should bail out of the script
     * and provide a descriptive fail message.
     * Required for OAuth2::GRANT_TYPE_REFRESH_TOKEN.
     *
     * @param string        $refreshToken The refresh token string to be stored.
     * @param IOAuth2Client $client       The client associated with this refresh token.
     * @param mixed         $data         Application data associated with the refresh token, such as a User object.
     * @param int           $expires      The timestamp when the refresh token will expire.
     * @param string        $scope        (optional) Scopes to be stored in space-separated string.
     *
     * @ingroup oauth2_section_6
     */

    public function createRefreshToken($refreshToken, IOAuth2Client $client, $data, $expires, $scope = null)
    {
        try {
            $clientId = $client->getPublicId();

            $sql = "INSERT INTO " . self::TABLE_REFRESH . " (oauth_token,
                                                            refresh_token,
                                                            client_id,
                                                            user_id,
                                                            expires,
                                                            scope)
                    VALUES (:oauth_token, :refresh_token, :client_id, :user_id, :expires, :scope)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':oauth_token', $refreshToken, \PDO::PARAM_STR);
            $stmt->bindParam(':refresh_token', $refreshToken, \PDO::PARAM_STR);
            $stmt->bindParam(':client_id', $clientId, \PDO::PARAM_STR);
            $stmt->bindParam(':user_id', $data, \PDO::PARAM_STR);
            $stmt->bindParam(':expires', $expires, \PDO::PARAM_INT);
            $stmt->bindParam(':scope', $scope, \PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }

    }

    /**
     * Grant access tokens for basic user credentials.
     *
     * Check the supplied username and password for validity.
     * You can also use the $client param to do any checks required based on a client, if you need that.
     * Required for OAuth2::GRANT_TYPE_USER_CREDENTIALS.
     *
     * @param IOAuth2Client $client   Client to check.
     * @param string        $username Username to check.
     * @param string        $password Password to check.
     *
     * @return bool|array Returns true if the username and password are valid or false if they aren't.
     * Moreover, if the username and password are valid, and you want to
     * verify the scope of a user's access, return an associative array
     * with the scope values as below. We'll check the scope you provide
     * against the requested scope before providing an access token:
     * @code
     * return array(
     *     'scope' => <stored scope values (space-separated string)>,
     * );
     * @endcode
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.3
     *
     * @ingroup oauth2_section_4
     */
    public function checkUserCredentials(IOAuth2Client $client, $username, $password)
    {
        try {

            $clientId = $client->getPublicId();

            $sql = 'SELECT id, password FROM '.self::TABLE_USERS.' WHERE username = :username';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':username', $username, \PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            if (false === password_verify($password, $result['password'])) {
                return false;
            }

            return array(
                'scope' => '',
                'data' => $result['id'],
            );

        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }
}
