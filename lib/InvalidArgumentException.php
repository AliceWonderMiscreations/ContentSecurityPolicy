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
     * Exception message when default-src is specified outside the constructor.
     *
     * @return \InvalidArgumentException
     */
    public static function invalidDefaultSrc()
    {
        return new self(sprintf(
            'The default-src directive can only be set in the condtructor.'
        ));
    }//end invalidDefaultSrc()

    
    /**
     * Exception message when child-src is specified.
     *
     * @return \InvalidArgumentException
     */
    public static function invalidChildSrc()
    {
        return new self(sprintf(
            'The deprecated child-src directive is automatically generated and can not be manually set.'
        ));
    }//end invalidChildSrc()

    
    /**
     * Exception message when an invalid fetch directive is specified
     *
     * @param string $arg The supplied invalid directive.
     *
     * @return \InvalidArgumentException
     */
    public static function invalidFetchDirective(string $arg)
    {
        return new self(sprintf(
            'The specified directive \'%s\' is not a valid CSP fetch directive.',
            $arg
        ));
    }//end invalidFetchDirective()
    
    /**
     * Exception message when an invalid document directive is specified
     *
     * @param string $arg The supplied invalid directive.
     *
     * @return \InvalidArgumentException
     */
    public static function invalidDocumentDirective(string $arg)
    {
        return new self(sprintf(
            'The specified directive \'%s\' is not a valid CSP document directive.',
            $arg
        ));
    }

    
    /**
     * Exception message when an invalid scheme source is specified
     *
     * @param string $arg The supplied invalid scheme source.
     *
     * @return \InvalidArgumentException
     */
    public static function invalidFetchScheme(string $arg)
    {
        return new self(sprintf(
            'A scheme-source must be on of \'https:\', \'data\', \'mediastream\', or \'filesystem\'. You supplied %s',
            $arg
        ));
    }//end invalidFetchScheme()
    
    /**
     * Exception message when an invalid hostname is specified
     *
     * @return \InvalidArgumentException
     */
    public static function invalidHostName()
    {
        return new self(sprintf(
            'A host must be a valid hostname with an optional single * wildcard at the start.'
        ));
    }//end invalidHostName()

    
    /**
     * Exception message when an invalid host is specified
     *
     * @return \InvalidArgumentException
     */
    public static function invalidHostSource()
    {
        return new self(sprintf(
            'A host can only include optional protocol, mandatory hostname or IP address, and optional port parameters'
        ));
    }//end invalidHostSource()

    
    /**
     * Exception message when an invalid host scheme is specified
     *
     * @return \InvalidArgumentException
     */
    public static function invalidHostScheme()
    {
        return new self(sprintf(
            'A host scheme can only be http or https'
        ));
    }//end invalidHostScheme()


    
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
    
    /**
     * Exception message when the supplied argument is not a valid mime type
     *
     * @param string $arg The mime that was supplied.
     *
     * @return \InvalidArgumentException
     */
    public static function badMime(string $arg)
    {
        return new self(sprintf(
            'The supplied argument \'%s\' is not a valid MIME type.',
            $arg
        ));
    }
    
    /**
     * Exception message when the supplied argument is not a valid sandbox value
     *
     * @param string $arg The value that was supplied.
     *
     * @return \InvalidArgumentException
     */
    public static function badSandboxValue(string $arg)
    {
        return new self(sprintf(
            'The supplied argument \'%s\' is not a valid CSP sandbox parameter.',
            $arg
        ));
    }
}//end class
