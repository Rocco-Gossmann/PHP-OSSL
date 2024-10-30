# PHP-OSSL

A small library that helps with En- and Decryption via PHP-OpenSSL.

## Usage


### Generate Keys for Asymetric Encryption
```php
<?php
    require_once __DIR__ . "/path/to/OSSL/OSSL.php";

    use rogoss\OSSL\OSSL;
    use rogoss\OSSL\Exception as OSSLException;

    $sPrivateKey = "";
    $sPublicKey = "";

    try {
        OSSL::KeyGen()->createNewKeys($sPrivateKey, $sPublicKey)

        echo "keys have been generated: \n", $sPrivateKey, "\n", $sPublicKey;

    } catch (OSSLException $ex) {
        echo "could not generate Keys => " , $ex->message();

    }
```


### Asymetric Encryption

```php
<?php
    require_once __DIR__ . "/path/to/OSSL/OSSL.php";

    use rogoss\OSSL\OSSL;

// Encrypt something using the Private Key
    $sEncryptedWithPrivateKey = OSSL::Encrypter()
        ->privateKey("your private key here")
        ->encrypt("secret message");

// Decrypt something using the Public Key
    $sDecrypted = OSSL::Decrypter()
        ->publicKey("your public key here")
        ->decrypt($sEncryptedWithPrivateKey);

// it also works in reverse
// -----------------------------------------------------

// Encrypt something using the Public Key
    $sEncryptedWithPublicKey = OSSL::Encrypter()
        ->publicKey("your public key here")
        ->encrypt("secret message");

// Decrypt something using the Private Key
    $sDecrypted = OSSL::Decrypter()
        ->privateKey("your private key here")
        ->decrypt($sEncryptedWithPublicKey);

```

### Symetric Encryption

```php
<?php 
    require_once __DIR__ . "/path/to/OSSL/OSSL.php";

    use rogoss\OSSL\OSSL;

// Encryption
    $sEncrypted = OSSL::BasicCrypter("password")
        ->encrypt("secret message");

// Decryption
    $sDecrypted = OSSL::BasicCrypter("password")
        ->decrypt($sEncrypted);

```

