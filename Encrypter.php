<?php

namespace rogoss\OSSL;

require_once __DIR__ . "/tCrypter.php";
require_once __DIR__ . "/Exception.php";

class Encrypter
{

    use tCrypter;

    public function encrypt($sData, $bRaw = false)
    {
        if ($this->bJSON) $sData = json_encode($sData);

        if (empty($this->sKey))
            throw new Exception("no private key", Exception::MISSING_KEY);

        $sEnc = "";
        if (!openssl_private_encrypt($sData, $sEnc, $this->sKey)) {
            $sErr = openssl_error_string();
            throw new Exception($sErr);
        }

        return $bRaw ? $sEnc : base64_encode($sEnc);
    }
}
