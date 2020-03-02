php-apple-signin
=======

PHP library to manage Sign In with Apple identifier tokens, and validate them server side passed through by the iOS client.

Based on Griffin Ledingham's php-apple-signin project. 3 major modifications on it:

1. remove >=php7.2 mandatory requirements.
2. compatible for multiple keys check(apple return 3 keys now).
3. import absent exception files from firebase's JWT project.

Installation
------------

Use composer to manage your dependencies and download php-apple-signin:

```bash
composer require lidouf/php-apple-signin
```

Example
-------
```php
<?php
use AppleSignIn\ASDecoder;

$clientUser = "example_client_user";
$identityToken = "example_encoded_jwt";

$appleSignInPayload = ASDecoder::getAppleSignInPayload($identityToken);

/**
 * Obtain the Sign In with Apple email and user creds.
 */
$email = $appleSignInPayload->getEmail();
$user = $appleSignInPayload->getUser();

/**
 * Determine whether the client-provided user is valid.
 */
$isValid = $appleSignInPayload->verifyUser($clientUser);

?>
```
