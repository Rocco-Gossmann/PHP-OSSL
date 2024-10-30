<?php

namespace rogoss\OSSL;

require_once __DIR__ . "/Encrypter.php";
require_once __DIR__ . "/Decrypter.php";
require_once __DIR__ . "/KeyGen.php";
require_once __DIR__ . "/Exception.php";


class OSSL
{

    public static function KeyGen(): KeyGen
    {
        return new KeyGen();
    }

    public static function Decrypter(): Decrypter
    {
        return new Decrypter();
    }

    public static function Encrypter(): Encrypter
    {
        return new Encrypter();
    }

    /**
     * Symetric - Encryption
     *
     * @param string $sPassPhrase 
     * @param string $iv 0 to 16 characters (less than 0 is padded with $sPassPhrase
     * @return 
     */
    public static function BasicCrypter($sPassPhrase, $iv = ""): OSSL
    {
        $i = new static();
        $i->sPassPhrase = $sPassPhrase;
        $i->sIV = $iv;

        while (strlen($i->sIV) < 16)
            $i->sIV .= $sPassPhrase;

        $i->sIV = substr($i->sIV, 0, 16);
        return $i;
    }

    private $sPassPhrase = "";
    private $sIV = "";
    private $bJSON = false;

    /**
     * Enable this, if you want to en-/decrypt Arrays or objects
     * @return 
     */
    public function json() : static {
        $this->bJSON = true; 
        return $this;
    }

    public function encrypt($sData, $bRaw = false)
    {
        if ($this->bJSON) $sData = json_encode($sData);

        return ($tmp = openssl_encrypt(
            $sData,
            'aes-128-cbc',
            $this->sPassPhrase,
            $bRaw ? OPENSSL_RAW_DATA : 0,
            $this->sIV
        )) ? $tmp : null ;
    }

    public function decrypt($sData, $bRaw = false)
    {
        $sDec = openssl_decrypt(
            $sData,
            'aes-128-cbc',
            $this->sPassPhrase,
            $bRaw ? OPENSSL_RAW_DATA : 0,
            $this->sIV
        );

        if ($sDec === false)
            return null;

        if ($this->bJSON) $sDec = json_decode($sDec, true);

        return $sDec;
    }

    private function __construct() {}
}
