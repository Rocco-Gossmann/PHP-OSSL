<?php

namespace rogoss\OSSL;

class KeyGen
{

    public function createNewKeys(&$sPrivateKey, &$sPublicKey)
    {
        $aConf = [
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];

        if (is_file($sConfFile = $this->_configFile()))
            $aConf['config'] = $sConfFile;

        $sPKey = openssl_pkey_new($aConf);
        if (!$sPKey) echo openssl_error_string();
        else {

            $sPrKey = "";
            if (!openssl_pkey_export($sPKey, $sPrKey, null, $aConf))
                echo "pkey_export error ", openssl_error_string();
            else {
                $sPuKey = (openssl_pkey_get_details($sPKey) ?? [])['key'] ?? false;

                if (empty($sPuKey))
                    echo "pkey_export error ", openssl_error_string();
                else {
                    $sData = "Hello World\nHowAre you 😁";

                    $sEnc = "";
                    $sDec = "";

                    openssl_private_encrypt($sData, $sEnc, $sPrKey);
                    openssl_public_decrypt($sEnc, $sDec, $sPuKey);

                    if ($sDec == $sData) {
                        $sPublicKey = $sPuKey;
                        $sPrivateKey = $sPrKey;
                    }
                }
            }
        }
    }

    public function createPublicKeyFromPrivate(string $sPrivateKey): string
    {
        $sPrivateKey = openssl_pkey_get_private($sPrivateKey);
        return (openssl_pkey_get_details($sPrivateKey) ?? [])['key'] ?? false;
    }

    // BM: Private Helpers
    private function _configFile(): string
    {
        $sConfFile = "/etc/ssl/openssl.cnf";

        if (!is_file($sConfFile) and !empty(getenv("OPENSSL_CONF")))
            $sConfFile = getenv("OPENSSL_CONF");

        if (empty($sConfFile) or !is_file($sConfFile))
            throw new Exception("missing config file. Please define the 'OPENSSL_CONF' Environment variable to define, what file to use", OSSLException::MISSING_CONFIG);

        return $sConfFile;
    }
}