<?php
declare(strict_types=1);

/**
 * Invalid Argument Exception class.
 *
 * @package AWonderPHP/ContentSecurityPolicy
 * @author  Alice Wonder <paypal@domblogger.net>
 * @license https://opensource.org/licenses/MIT MIT
 * @link    https://github.com/AliceWonderMiscreations/ContentSecurityPolicy
 */

namespace AWonderPHP\ContentSecurityPolicy;

/**
 * Throws a \InvalidArgumentException exception.
 */
class InvalidArgumentException extends \InvalidArgumentException
{
    /**
     * Exception message when an invalid directive is specified
     *
     * @param string $arg The supplied invalid directive.
     *
     * @return \InvalidArgumentException
     */
    public static function invalidDirective(string $arg)
    {
        return new self(sprintf(
            'The specified directive \'%s\' either is not a valid CSP directive or can not be set with this function.',
            $arg
        ));
    }//end invalidDirective()

    
    /**
     * Exception message when an invalid sandbox policy is specified
     *
     * @param string $arg The supplied invalid policy.
     *
     * @return \InvalidArgumentException
     */
    public static function invalidSandboxPolicy(string $arg)
    {
        return new self(sprintf(
            'The specified policy \'%s\' is not a valid sandbox directive policy.',
            $arg
        ));
    }//end invalidSandboxPolicy()

     
    /**
     * Exception message when the supplied nonce is not valid.
     *
     * @param string $arg The nonce that was supplied.
     *
     * @return \InvalidArgumentException
     */
    public static function badNonce(string $arg)
    {
        return new self(sprintf(
            'The nonce must be a 128-bit or larger nonce encoded as a base64 string. You supplied \'%s\'.',
            $arg
        ));
    }//end badNonce()
    
    /**
     * Exception message when the supplied hash algo is not valid.
     *
     * @return \InvalidArgumentException
     */
    public static function badAlgo()
    {
        return new self(sprintf(
            'The hash algorithm must be sha256, sha384, or sha512.'
        ));
    }//end badAlgo()
    
    /**
     * Exception message when the supplied hash digest is not valid.
     *
     * @return \InvalidArgumentException
     */
    public static function badHash()
    {
        return new self(sprintf(
            'The hash must be a valid hex or base64 encoded hash.'
        ));
    }//end badHash()
}//end class
