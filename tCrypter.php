<?php namespace rogoss\OSSL;

trait tCrypter {
    
    private $bJSON = false;
    private $sKey = "";

    public function __construct(string $sKey) {
        $this->sKey = $sKey;
    }

    public function json()
    {
        $this->bJSON = true;
        return $this;
    }

}
