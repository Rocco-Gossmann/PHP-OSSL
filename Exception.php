<?php namespace rogoss\OSSL;

class Exception extends \Exception
{
    const OPENSSL_ERROR = 0;
    const MISSING_KEY = 1;
    const MISSING_CONFIG = 2;
    const KEYGEN_ERROR = 3;
}
