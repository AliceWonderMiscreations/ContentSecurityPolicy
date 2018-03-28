<?php
declare(strict_types=1);

/**
 * Test suite for \AWonderPHP\ContentSecurityPolicy
 *
 * @package AWonderPHP/ContentSecurityPolicy
 * @author  Alice Wonder <paypal@domblogger.net>
 * @license https://opensource.org/licenses/MIT MIT
 * @link    https://github.com/AliceWonderMiscreations/ContentSecurityPolicy
 */

use PHPUnit\Framework\TestCase;

// @codingStandardsIgnoreLine
final class FetchDirectiveStyleSrcTest extends TestCase
{
    /**
     * Tests header output when explicitly set to *
     *
     * @return void
     */
    public function testParameterWildcardForEverything(): void
    {
        $expected = 'default-src \'none\'; style-src *;';
        $directive = 'style-src';
        $policy = '*';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParameterWildcardForEverything()


  
    /**
     * Tests header output when explicitly set to 'self'
     *
     * @return void
     */
    public function testParameterSelf(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\';';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParameterSelf()


    
    /**
     * Tests header output when explicitly set to 'none'
     *
     * @return void
     */
    public function testParameterNone(): void
    {
        $expected = 'default-src \'self\'; style-src \'none\'; plugin-types image/svg+xml application/pdf;';
        $directive = 'style-src';
        $policy = 'none';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParameterNone()


    
    /**
     * Tests header output when explicitly set to 'https:'
     *
     * @return void
     */
    public function testSchemeParamaterHttps(): void
    {
        $expected = 'default-src \'none\'; style-src https:;';
        $directive = 'style-src';
        $policy = 'https:';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testSchemeParamaterHttps()


    
    /**
     * Tests header output when explicitly set to 'self https:'
     *
     * @return void
     */
    public function testParamatersSelfAndSchemeHttps(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\' https:;';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https:';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParamatersSelfAndSchemeHttps()


    
    /**
     * Tests header output when explicitly set to 'self https:' then set to 'none'
     *
     * @return void
     */
    public function testResetParamatersToNone(): void
    {
        $expected = 'default-src \'self\'; style-src \'none\'; plugin-types image/svg+xml application/pdf;';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https:';
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'none';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testResetParamatersToNone()


    
    /**
     * Tests header output when explicitly set to 'self https:' then set to 'none'
     *
     * @return void
     */
    public function testResetParametersToSelf(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\';';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https:';
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'self';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testResetParametersToSelf()


    
    /**
     * Tests header output when explicitly set to 'self example.org'
     *
     * @return void
     */
    public function testParamatersSelfAndHostname(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\' example.org;';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'example.org';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParamatersSelfAndHostname()


    
    /**
     * Tests header output when explicitly set to 'self example.org:443'
     *
     * @return void
     */
    public function testParamatersSelfAndHostnameWithPort(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\' example.org:443;';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'example.org:443';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParamatersSelfAndHostnameWithPort()


    
    /**
     * Tests header output when explicitly set to 'self https://example.org'
     *
     * @return void
     */
    public function testParametersSelfAndSchemeWithHostname(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\' https://example.org;';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https://example.org';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfAndSchemeWithHostname()

    
    /**
     * Tests header output when explicitly set to 'self https://example.org:443'
     *
     * @return void
     */
    public function testParametersSelfAndSchemeWithHostnameWithPort(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\' https://example.org:443;';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https://example.org:443';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfAndSchemeWithHostnameWithPort()


    
    /**
     * Tests header output when explicitly set to 'self *.example.org'
     *
     * @return void
     */
    public function testParametersSelfWithWildcardInHostname(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\' *.example.org;';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = '*.example.org';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfWithWildcardInHostname()

    
    /**
     * Tests header output when explicitly set to 'self *.example.org:443'
     *
     * @return void
     */
    public function testParametersSelfWithWildcardInHostnameWithPort(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\' *.example.org:443;';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = '*.example.org:443';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfWithWildcardInHostnameWithPort()


    
    /**
     * Tests header output when explicitly set to 'self *.example.org:*'
     *
     * @return void
     */
    public function testParametersSelfWithWildcardInHostnameAndInPort(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\' *.example.org:*;';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = '*.example.org:*';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfWithWildcardInHostnameAndInPort()


    
    /**
     * Tests header output when explicitly set to 'self https://*.example.org:*'
     *
     * @return void
     */
    public function testParametersSelfWithSchemeAndWildcardInHostnameAndInPort(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\' https://*.example.org:*;';
        $directive = 'style-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https://*.example.org:*';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfWithSchemeAndWildcardInHostnameAndInPort()

    
    /**
     * Tests header output when copying default and appending
     *
     * @return void
     */
    public function testCopyDefaultAddHost(): void
    {
        $expected = 'default-src \'self\' https://cdn.example.net; style-src \'self\' https://cdn.example.net https://*.elsewhere.com; plugin-types image/svg+xml application/pdf;';
        $directive = 'style-src';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self https://cdn.example.net');
        $csp->copyDefaultFetchPolicy($directive);
        $policy = 'https://*.elsewhere.com';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testCopyDefaultAddHost()

    /**
     * Tests header output with unsafe-inline.
     *
     * @return void
     */
    public function testStyleSrcUnsafeInline(): void
    {
        $expected = 'default-src \'none\'; style-src \'unsafe-inline\';';
        $directive = 'style-src';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('style-src', 'unsafe-inline');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testStyleSrcUnsafeInline()

    
    /**
     * Tests header output with hash via addFetchPolicy
     *
     * @return void
     */
    public function testSrcAddHashViaAddFetchPolicy(): void
    {
        $raw = random_bytes(32);
        $hex = bin2hex($raw);
        $b64 = base64_encode($raw);
        $expected = 'default-src \'none\'; style-src \'sha256-' . $b64 . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('style-src', 'sha256-' . $hex);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
        // reset for base64 test
        $csp->addFetchPolicy('style-src', 'none');
        $actual = $csp->buildHeader();
        $this->assertEquals('default-src \'none\';', $actual);
        // base64 test
        $csp->addFetchPolicy('style-src', 'sha256-' . $b64);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testSrcAddHashViaAddFetchPolicy()

    
    /**
     * Tests header output with hash via addStyleHash
     *
     * @return void
     */
    public function testSrcAddHashViaAddStyleHash(): void
    {
        $raw = random_bytes(32);
        $hex = bin2hex($raw);
        $b64 = base64_encode($raw);
        $expected = 'default-src \'none\'; style-src \'sha256-' . $b64 . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addStyleHash('sha256', $hex);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
        // reset for base64 test
        $csp->addFetchPolicy('style-src', 'none');
        $actual = $csp->buildHeader();
        $this->assertEquals('default-src \'none\';', $actual);
        // base64 test
        $csp->addStyleHash('sha256', $b64);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testSrcAddHashViaAddStyleHash()


    /**
     * Tests header output with nonce via addFetchPolicy
     *
     * @return void
     */
    public function testScrAddNonceViaAddFetchPolicy(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'none\'; style-src \'nonce-' . $nonce . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('style-src', 'nonce-' . $nonce);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScrAddNonceViaAddFetchPolicy()
    
    /**
     * Tests header output with nonce via addNonce
     *
     * @return void
     */
    public function testScrAddNonceViaAddNonce(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'none\'; style-src \'nonce-' . $nonce . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addNonce('style-src', $nonce);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Tests header output unsafe-inline then nonce.
     * Nonce should take precedence.
     *
     * @return void
     */
    public function testStyleSrcUnsafeInlineThenNonce(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'none\'; style-src \'nonce-' . $nonce . '\';';
        $directive = 'style-src';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('style-src', 'unsafe-inline');
        $csp->addNonce('style-src', $nonce);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Tests header output nonce then unsafe-inline.
     * Nonce should take precedence.
     *
     * @return void
     */
    public function testStyleSrcNonceThenUnsafeInline(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'none\'; style-src \'nonce-' . $nonce . '\';';
        $directive = 'style-src';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addNonce('style-src', $nonce);
        $csp->addFetchPolicy('style-src', 'unsafe-inline');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    
    
    
     







}//end class

?>