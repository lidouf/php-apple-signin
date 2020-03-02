<?php

namespace AppleSignIn;

use AppleSignIn\Vendor\JWK;
use AppleSignIn\Vendor\JWT;

/**
 * Decode Sign In with Apple identity token, and produce an ASPayload for
 * utilizing in backend auth flows to verify validity of provided user creds.
 *
 * @package  AppleSignIn\ASDecoder
 * @author   Griffin Ledingham <gcledingham@gmail.com>
 * @author   Lidouf <lidouf@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/GriffinLedingham/php-apple-signin
 * @link     https://github.com/lidouf/php-apple-signin
 */
class ASDecoder {
    /**
     * Parse a provided Sign In with Apple identity token.
     *
     * @param string $identityToken
     * @throws \Exception
     *
     * @return object|null
     */
    public static function getAppleSignInPayload($identityToken)
    {
        $identityPayload = self::decodeIdentityToken($identityToken);
        return new ASPayload($identityPayload);
    }

    /**
     * Decode the Apple encoded JWT using Apple's public key for the signing.
     *
     * @param string $identityToken
     * @throws \Exception
     *
     * @return object
     */
    public static function decodeIdentityToken($identityToken) {
        //fetch public key(s) from apple
        $publicKey = self::fetchPublicKey();
        //allowed algorithms
        $algs = ['HS256', 'HS384', 'HS512', 'RS256'];
        //decode
        $payload = JWT::decode($identityToken, $publicKey, $algs);

        return $payload;
    }

    /**
     * Fetch Apple's public key from the auth/keys REST API to use to decode
     * the Sign In JWT.
     *
     * @throws \Exception
     * @return array | string
     */
    public static function fetchPublicKey() {
        $publicKeys = file_get_contents('https://appleid.apple.com/auth/keys');
        $decodedPublicKeys = json_decode($publicKeys, true);

        if(!isset($decodedPublicKeys['keys']) || count($decodedPublicKeys['keys']) < 1) {
            throw new \Exception('Invalid key format.');
        }

        $ret = [];
        foreach ($decodedPublicKeys['keys'] as $parsedKeyData) {
            $parsedPublicKey= JWK::parseKey($parsedKeyData);
            $publicKeyDetails = openssl_pkey_get_details($parsedPublicKey);
            $key = isset($publicKeyDetails['key']) ? $publicKeyDetails['key'] : null;
            if (!isset($parsedKeyData['kid'])) {
                if (count($decodedPublicKeys['keys']) == 1) {
                    //if there's only one key included and it has no `kid` field in it we can just return this key.
                    return $key;
                } else {
                    continue;
                }
            } else {
                $ret[$parsedKeyData['kid']] = $key;
            }
        }

        return $ret;
    }
}

/**
 * A class decorator for the Sign In with Apple payload produced by
 * decoding the signed JWT from a client.
 */
class ASPayload {
    protected $_instance;

    public function __construct($instance) {
        if(is_null($instance)) {
            throw new \Exception('ASPayload received null instance.');
        }
        $this->_instance = $instance;
    }

    public function __call($method, $args) {
        return call_user_func_array(array($this->_instance, $method), $args);
    }

    public function __get($key) {
        return $this->_instance->$key;
    }

    public function __set($key, $val) {
        return $this->_instance->$key = $val;
    }

    public function getEmail() {
        return (isset($this->_instance->email)) ? $this->_instance->email : null;
    }

    public function getUser() {
        return (isset($this->_instance->sub)) ? $this->_instance->sub : null;
    }

    public function verifyUser($user) {
        return $user === $this->getUser();
    }
}
