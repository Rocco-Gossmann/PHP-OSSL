<?php namespace Tests;

require_once __DIR__ . "/OSSL.php";

use \PHPUnit\Framework\TestCase;
use \rogoss\OSSL\OSSL;

class TestOSSL extends TestCase {

    const ENC_PAYLOAD = "Hello World";
    const JSON_PAYLOAD = ["Hello"=> "World"];

    static $sPubKey = "";
    static $sPrivKey = "";
    static $sEncrypted = "";
    
    public function testKeyGen()
    {
        OSSL::KeyGen()->createNewKeys(self::$sPrivKey, self::$sPubKey);

        $this->assertNotEmpty(self::$sPubKey, "expected public key to not be empty");
        $this->assertNotEmpty(self::$sPrivKey, "expected private key to not be empty");
    }

    public function testGenPublicKeyFromPrivateKey()
    {
        $this->assertNotEmpty(self::$sPrivKey, "expected private key to not be empty");
        self::$sPubKey = OSSL::KeyGen()->createPublicKeyFromPrivate(self::$sPrivKey);
        $this->assertNotEmpty(self::$sPubKey, "expected public key to not be empty");
    }

    public function testRSAEncrytion() {
        $this->assertNotEmpty(self::$sPrivKey, "expected private key to not be empty");

        self::$sEncrypted = OSSL::RSAEncrypter(self::$sPrivKey)->encrypt(self::ENC_PAYLOAD, false);
        $this->assertMatchesRegularExpression("/^[0-9a-z+\/]+={0,2}$/i", self::$sEncrypted, "expected encrypted value to be a base64 encoded value");
    }

    public function testRSADecryption() {
        $this->assertNotEmpty(self::$sPubKey, "expected public key to not be empty");
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted content to not be empty");

        $sDecrypted = OSSL::RSADecrypter(self::$sPubKey)->decrypt(self::$sEncrypted, false);
        $this->assertEquals(self::ENC_PAYLOAD, $sDecrypted, "expected decrypted data to match what was encrypted");
    }

    public function testRSADecryptionWithWrongKey() {
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted content to not be empty");
        $sPr=$sPu="";
        OSSL::KeyGen()->createNewKeys($sPr, $sPu);

        $this->expectException("\\rogoss\\OSSL\\Exception");
        $this->expectExceptionCode(\rogoss\OSSL\Exception::OPENSSL_ERROR);
        OSSL::RSADecrypter($sPu)->decrypt(self::$sEncrypted, false);
    }

    public function testRSAEncryptionRaw() {
        $this->assertNotEmpty(self::$sPrivKey, "expected private key to not be empty");

        self::$sEncrypted = OSSL::RSAEncrypter(self::$sPrivKey)->encrypt(self::ENC_PAYLOAD, true);
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted value to not be empty");
        $this->assertNotEquals(self::ENC_PAYLOAD, self::$sEncrypted, "expected encrypted value to not be empty");
    }

    public function testRSADecryptionRaw() {
        $this->assertNotEmpty(self::$sPubKey, "expected public key to not be empty");
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted content to not be empty");

        $sDecrypted = OSSL::RSADecrypter(self::$sPubKey)->decrypt(self::$sEncrypted, true);
        $this->assertEquals(self::ENC_PAYLOAD, $sDecrypted, "expected decrypted data to match what was encrypted");
    }

    public function testRSAEncryptionJSON() {
        $this->assertNotEmpty(self::$sPrivKey, "expected private key to not be empty");

        self::$sEncrypted = OSSL::RSAEncrypter(self::$sPrivKey)->json()->encrypt(self::JSON_PAYLOAD);
        $this->assertMatchesRegularExpression("/^[0-9a-z+\/]+={0,2}$/i", self::$sEncrypted, "expected encrypted value to be a base64 encoded value");
    }

    public function testRSADecryptionJSON() {
        $this->assertNotEmpty(self::$sPubKey, "expected public key to not be empty");
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted content to not be empty");

        $aDecrypted = OSSL::RSADecrypter(self::$sPubKey)->json()->decrypt(self::$sEncrypted);
        $this->assertSame(self::JSON_PAYLOAD, $aDecrypted);
    }

    public function testRSAEncryptionJSONRaw() {
        $this->assertNotEmpty(self::$sPrivKey, "expected private key to not be empty");

        self::$sEncrypted = OSSL::RSAEncrypter(self::$sPrivKey)->json()->encrypt(self::JSON_PAYLOAD, true);
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted value to not be empty");
    }


    public function testRSADecryptionJSONRaw() {
        $this->assertNotEmpty(self::$sPubKey, "expected public key to not be empty");
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted content to not be empty");

        $aDecrypted = OSSL::RSADecrypter(self::$sPubKey)->json()->decrypt(self::$sEncrypted, true);
        $this->assertSame(self::JSON_PAYLOAD, $aDecrypted, "expected decrypted data to match what was encrypted");
    }

    public function testBasicCrypterEncrypt() {
        self::$sEncrypted = OSSL::BasicCrypter("hello", "123")->encrypt(self::ENC_PAYLOAD);
        $this->assertMatchesRegularExpression("/^[0-9a-z+\/]+={0,2}$/i", self::$sEncrypted, "expected encrypted value to be a base64 encoded value");
    }

    public function testBasicCrypterDecrypt() {
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted content to not be empty");
        $sDec = OSSL::BasicCrypter("hello", "123")->decrypt(self::$sEncrypted);
        $this->assertEquals(self::ENC_PAYLOAD, $sDec);
    }

    public function testBasicCrypterDecryptWithWongPassword() {
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted content to not be empty");
        $this->expectException("\\rogoss\\OSSL\\Exception");
        $this->expectExceptionCode(\rogoss\OSSL\Exception::OPENSSL_ERROR);
        OSSL::BasicCrypter("world", "123")->decrypt(self::$sEncrypted);
    }

    public function testBasicCrypterDecryptWithWongIV() {
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted content to not be empty");
        $sDec = OSSL::BasicCrypter("hello", "456")->decrypt(self::$sEncrypted);
        $this->assertNotEquals(self::ENC_PAYLOAD, $sDec);
    }

    public function testBasicCrypterEncryptJSON() {
        self::$sEncrypted = OSSL::BasicCrypter("hello", "123")->json()->encrypt(self::JSON_PAYLOAD);
        $this->assertMatchesRegularExpression("/^[0-9a-z+\/]+={0,2}$/i", self::$sEncrypted, "expected encrypted value to be a base64 encoded value");
    }

    public function testBasicCrypterDecryptJSON() {
        $this->assertNotEmpty(self::$sEncrypted, "expected encrypted content to not be empty");
        $mDec = OSSL::BasicCrypter("hello", "123")->json()->decrypt(self::$sEncrypted);
        $this->assertSame(self::JSON_PAYLOAD, $mDec);
    }

}
