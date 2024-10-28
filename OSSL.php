<?php

namespace rogoss\OSSL;

require_once __DIR__ . "/tCrypter.php";
require_once __DIR__ . "/Decrypter.php";
require_once __DIR__ . "/Encrypter.php";
require_once __DIR__ . "/KeyGen.php";
require_once __DIR__ . "/Exception.php";


class OSSL
{

    use tCrypter;

    public static function KeyGen(): KeyGen
    {
        return new KeyGen();
    }

    public static function RSADecrypter(string $sPubKey): Decrypter
    {
        return new Decrypter($sPubKey);
    }

    public static function RSAEncrypter(string $sPrivKey): Encrypter
    {
        return new Encrypter($sPrivKey);
    }


    public static function BasicCrypter($sPassPhrease, $iv = ""): OSSL
    {
        $i = new static();
        $i->sPassPhrease = $sPassPhrease;
        $i->sIV = $iv;

        while (strlen($i->sIV) < 16)
            $i->sIV .= $sPassPhrease;

        $i->sIV = substr($i->sIV, 0, 16);
        return $i;
    }

    private $sPassPhrease = "";
    private $sIV = "";

    public function encrypt($sData, $bRaw = false)
    {
        if ($this->bJSON) $sData = json_encode($sData);

        return openssl_encrypt(
            $sData,
            'aes-128-cbc',
            $this->sPassPhrease,
            $bRaw ? OPENSSL_RAW_DATA : 0,
            $this->sIV
        );
    }

    public function decrypt($sData, $bRaw = false)
    {
        $sDec = openssl_decrypt(
            $sData,
            'aes-128-cbc',
            $this->sPassPhrease,
            $bRaw ? OPENSSL_RAW_DATA : 0,
            $this->sIV
        );

        if ($sDec === false)
            throw new Exception(openssl_error_string(), Exception::OPENSSL_ERROR);

        if ($this->bJSON) $sDec = json_decode($sDec, true);

        return $sDec;
    }

    private function __construct() {}
}
