<?php
declare(strict_types=1);

/**
 * Test suite for \AWonderPHP\ContentSecurityPolicy.
 *
 * @package AWonderPHP/ContentSecurityPolicy
 * @author  Alice Wonder <paypal@domblogger.net>
 * @license https://opensource.org/licenses/MIT MIT
 * @link    https://github.com/AliceWonderMiscreations/ContentSecurityPolicy
 */

use PHPUnit\Framework\TestCase;

// @codingStandardsIgnoreLine
final class ContentSecurityPolicyTest extends TestCase
{
    /**
     * Tests header output when null parameter specified to constructor.
     *
     * @return void
     */
    public function testBasicDefault(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'none\'; connect-src \'self\'; img-src \'self\'; media-src \'self\'; script-src \'self\'; style-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy();
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testBasicDefault()

    /**
     * Tests header output when 'self' parameter specified to constructor.
     *
     * @return void
     */
    public function testDefaultSelf(): void
    {
        $expected = 'default-src \'self\'; plugin-types image/svg+xml application/pdf;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultSelf()

    /**
     * Tests header output when 'none' parameter specified to constructor.
     *
     * @return void
     */
    public function testDefaultNone(): void
    {
        $expected = 'default-src \'none\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNone()

    /**
     * Tests header output when '*' parameter specified to constructor.
     *
     * @return void
     */
    public function testDefaultWildcard(): void
    {
        $expected = 'default-src *; plugin-types image/svg+xml application/pdf;';
        $csp = @new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('*');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultWildcard()

    /**
     * Tests header output when 'https:' parameter specified to constructor.
     *
     * @return void
     */
    public function testDefaultHttps(): void
    {
        $expected = 'default-src https:; plugin-types image/svg+xml application/pdf;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('https:');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultHttps()

    /**
     * Tests header output when 'self https://example.org' parameter specified to constructor.
     *
     * @return void
     */
    public function testDefaultSelfPlusSchemeAndHostname(): void
    {
        $expected = 'default-src \'self\' https://example.org; plugin-types image/svg+xml application/pdf;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self https://example.org');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultSelfPlusSchemeAndHostname()

    /**
     * Tests header output when 'self https://example.org unsafe-inline' parameters specified to constructor.
     *
     * @return void
     */
    public function testDefaultSelfPlusSchemeAndHostnameAndUnsafeInline(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'self\' https://example.org \'unsafe-inline\'; plugin-types image/svg+xml application/pdf;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self https://example.org unsafe-inline');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultSelfPlusSchemeAndHostnameAndUnsafeInline()

    /**
     * Tests header output when 'self unsafe-eval' parameters specified to constructor.
     *
     * @return void
     */
    public function testDefaultSelfUnsafeEval(): void
    {
        $expected = 'default-src \'self\' \'unsafe-eval\'; plugin-types image/svg+xml application/pdf;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self unsafe-eval');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultSelfUnsafeEval()

    /**
     * Tests header output when 'self nonce-foo' parameters specified to constructor.
     *
     * @return void
     */
    public function testDefaultSelfWithNonce(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $arg = 'self nonce-' . $nonce;
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy($arg);
        $expected = 'default-src \'self\' \'nonce-' . $nonce . '\'; plugin-types image/svg+xml application/pdf;';
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultSelfWithNonce()

    /**
     * Tests header output when 'nonce-foo strict-dynamic' parameters specified to constructor.
     *
     * @return void
     */
    public function testDefaultWithNonceAndStrictDynamic(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $arg = 'nonce-' . $nonce . ' strict-dynamic';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy($arg);
        $expected = 'default-src \'nonce-' . $nonce . '\' \'strict-dynamic\';';
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultWithNonceAndStrictDynamic()

    /**
     * Tests header output only 'strict-dynamic' parameter specified to constructor.
     *
     * @return void
     */
    public function testDefaultWithOnlyStrictDynamic(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $arg = 'strict-dynamic';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy($arg);
        $expected = 'default-src \'none\';';
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultWithOnlyStrictDynamic()

    /**
     * Test script hash with base64 hash.
     *
     * @return void
     */
    public function testScriptHashSha256Base64(): void
    {
        $raw = random_bytes(32);
        $hash = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha256-' . $hash . '\';';
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy('object-src', 'none');
        $csp->addScriptHash('sha256', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptHashSha256Base64()

    /**
     * Test script hash with hex hash.
     *
     * @return void
     */
    public function testScriptHashSha256Hex(): void
    {
        $raw = random_bytes(32);
        $hash64 = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha256-' . $hash64 . '\';';
        $hash = bin2hex($raw);
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy('object-src', 'none');
        $csp->addScriptHash('sha256', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptHashSha256Hex()

    /**
     * Test script hash sha384 with base64 hash.
     *
     * @return void
     */
    public function testScriptHashSha384Base64(): void
    {
        $raw = random_bytes(48);
        $hash = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha384-' . $hash . '\';';
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy('object-src', 'none');
        $csp->addScriptHash('sha384', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptHashSha384Base64()

    /**
     * Test script hash 384 with hex hash.
     *
     * @return void
     */
    public function testScriptHashSha384Hex(): void
    {
        $raw = random_bytes(48);
        $hash64 = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha384-' . $hash64 . '\';';
        $hash = bin2hex($raw);
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy('object-src', 'none');
        $csp->addScriptHash('sha384', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptHashSha384Hex()

    /**
     * Test script hash sha384 with base64 hash.
     *
     * @return void
     */
    public function testScriptHashSha512Base64(): void
    {
        $raw = random_bytes(64);
        $hash = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha512-' . $hash . '\';';
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy('object-src', 'none');
        $csp->addScriptHash('sha512', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptHashSha512Base64()

    /**
     * Test script hash 384 with hex hash.
     *
     * @return void
     */
    public function testScriptHashSha512Hex(): void
    {
        $raw = random_bytes(64);
        $hash64 = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha512-' . $hash64 . '\';';
        $hash = bin2hex($raw);
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy('object-src', 'none');
        $csp->addScriptHash('sha512', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptHashSha512Hex()
}//end class

?>