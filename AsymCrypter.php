<?php

namespace rogoss\OSSL;

class AsymCrypter
{

    protected ?\Closure $hJSON = null;
    protected string $sKey = "";
    protected string $sCryptFunction = "";

    protected function __construct(
        private string $sPublicKeyFunction,
        private string $sPrivateKeyFunction,
        private \Closure $hJSONHandler
    ) {
        $this->sCryptFunction = $this->sPublicKeyFunction;
        $this->hJSON = fn($i) => $i;
    }

    final public function publicKey(string $sKey): static
    {
        $this->sKey = $sKey;
        $this->sCryptFunction = $this->sPublicKeyFunction;

        return $this;
    }

    final public function privateKey(string $sKey): static
    {
        $this->sKey = $sKey;
        $this->sCryptFunction = $this->sPrivateKeyFunction;

        return $this;
    }

    
    /**
     * Enable this, if you want to en-/decrypt Arrays or objects
     * @return 
     */
    public function json(): static
    {
        $this->hJSON = $this->hJSONHandler;
        return $this;
    }
}
