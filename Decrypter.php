<?php

namespace rogoss\OSSL;

require_once __DIR__ . "/AsymCrypter.php";
require_once __DIR__ . "/Exception.php";

class Decrypter extends AsymCrypter {

    /** @ignore */
    public function __construct() {
        parent::__construct(
            "openssl_public_decrypt", 
            "openssl_private_decrypt",
            fn($i) => json_decode($i, true)
        );
    }

    public function decrypt($sData, $bRaw = false)
    {
        if (empty($this->sKey))
            throw new Exception("no key, use either \$this->publicKey or \$this->privateKey to set one", Exception::MISSING_KEY);

        $sRaw = $bRaw ? $sData : base64_decode($sData);

        $sDec = "";
        if (!($this->sCryptFunction)($sRaw, $sDec, $this->sKey))
            return null;

        return ($this->hJSON)($sDec);
    }
}
