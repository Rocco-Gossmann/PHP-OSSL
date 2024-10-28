<?php

namespace rogoss\OSSL;

require_once __DIR__ . "/tCrypter.php";
require_once __DIR__ . "/Exception.php";

class Decrypter
{

    use tCrypter;

    public function decrypt($sData, $bRaw = false)
    {
        $sRaw = $bRaw ? $sData : base64_decode($sData);
        if (empty($this->sKey))
            throw new Exception("no public key", Exception::MISSING_KEY);

        $sDec = "";
        if (!openssl_public_decrypt($sRaw, $sDec, $this->sKey))
            throw new Exception(openssl_error_string());

        if ($this->bJSON) $sDec = json_decode($sDec, true);

        
        return $sDec;
    }
}
