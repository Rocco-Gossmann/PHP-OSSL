<?php

namespace rogoss\OSSL;

require_once __DIR__ . "/AsymCrypter.php";
require_once __DIR__ . "/Exception.php";

class Encrypter extends AsymCrypter
{

    /** @ignore */
    public function __construct() {
        parent::__construct(
            "openssl_public_encrypt",
            "openssl_private_encrypt",
            fn($i) => json_encode($i)  
        ); 
    }

    public function encrypt($sData, $bRaw = false)
    {
        if (empty($this->sKey))
            throw new Exception("no key, use either \$this->publicKey or \$this->privateKey to set one", Exception::MISSING_KEY);

        $sData = ($this->hJSON)($sData);

        $sEnc = "";
        if (!($this->sCryptFunction)($sData, $sEnc, $this->sKey)) 
            return null;

        return $bRaw ? $sEnc : base64_encode($sEnc);
    }
}
