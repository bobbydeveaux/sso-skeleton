<?php

namespace DVO;

use OAuth2\Model\IOAuth2AccessToken;
use OAuth2\Model\IOAuth2AuthCode;
use OAuth2\Model\IOAuth2Client;

class OAuth2 extends \OAuth2\OAuth2
{
    /**
     * Handle the creation of access token, also issue refresh token if support.
     *
     * This belongs in a separate factory, but to keep it simple, I'm just keeping it here.
     *
     * @param IOAuth2Client $client
     * @param mixed         $data
     * @param string|null   $scope
     * @param int|null      $access_token_lifetime How long the access token should live in seconds
     * @param bool          $issue_refresh_token Issue a refresh tokeniIf true and the storage mechanism supports it
     * @param int|null      $refresh_token_lifetime How long the refresh token should life in seconds
     *
     * @return array
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5
     *
     * @ingroup oauth2_section_5
     */
    public function createAccessToken(IOAuth2Client $client, $data, $scope = null, $access_token_lifetime = null, $issue_refresh_token = true, $refresh_token_lifetime = null)
    {
        $token = array(
            "access_token" => $this->genAccessToken(),
            "expires_in" => ($access_token_lifetime ?: $this->getVariable(self::CONFIG_ACCESS_LIFETIME)),
            "token_type" => $this->getVariable(self::CONFIG_TOKEN_TYPE),
            "scope" => $scope,
            "id" => $data,
        );

        $this->storage->createAccessToken(
            $token["access_token"],
            $client,
            $data,
            time() + ($access_token_lifetime ?: $this->getVariable(self::CONFIG_ACCESS_LIFETIME)),
            $scope
        );

        // Issue a refresh token also, if we support them
        if ($this->storage instanceof IOAuth2RefreshTokens && $issue_refresh_token === true) {
            $token["refresh_token"] = $this->genAccessToken();
            $this->storage->createRefreshToken(
                $token["refresh_token"],
                $client,
                $data,
                time() + ($refresh_token_lifetime ?: $this->getVariable(self::CONFIG_REFRESH_LIFETIME)),
                $scope
            );

            // If we've granted a new refresh token, expire the old one
            if (null !== $this->oldRefreshToken) {
                $this->storage->unsetRefreshToken($this->oldRefreshToken);
                $this->oldRefreshToken = null;
            }
        }

        if ($this->storage instanceof IOAuth2GrantCode) {
            if (null !== $this->usedAuthCode) {
                $this->storage->markAuthCodeAsUsed($this->usedAuthCode->getToken());
                $this->usedAuthCode = null;
            }
        }

        return $token;
    }
}
