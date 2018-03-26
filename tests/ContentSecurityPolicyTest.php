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
final class ContentSecurityPolicyTest extends TestCase
{
    /**
     * Tests header output when null parameter specified to constructor
     *
     * @return void
     */
    public function testBasicDefault(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\'; img-src \'self\'; media-src \'self\'; script-src \'self\'; style-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy();
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testBasicDefault()

    /**
     * Tests header output when 'self' parameter specified to constructor
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
     * Tests header output when 'none' parameter specified to constructor
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
     * Tests header output when '*' parameter specified to constructor
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
     * Tests header output when 'https:' parameter specified to constructor
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
     * Tests header output when 'self https://example.org' parameter specified to constructor
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
     * Tests generation of nonce. Should be 16-byte when argument null, 16-byte when argument
     * is < 16, > 16 bytes byte when argument is >16. (2 hex = 1 byte)
     *
     * @return void
     */
    public function testGenerateNonce(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $raw = base64_decode($nonce);
        $hex = bin2hex($raw);
        $len = strlen($hex);
        $this->assertEquals(32, $len);
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce(6);
        $raw = base64_decode($nonce);
        $hex = bin2hex($raw);
        $len = strlen($hex);
        $this->assertEquals(32, $len);
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce(24);
        $raw = base64_decode($nonce);
        $hex = bin2hex($raw);
        $len = strlen($hex);
        $this->assertEquals(48, $len);
    }//end testGenerateNonce()
    
    /**
     * Test script with base64 nonce
     *
     * @return void
     */
    public function testScriptNonceBase64(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'nonce-' . $nonce . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy('object-src', 'none');
        $csp->addNonce('script-src', $nonce);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptNonceBase64()

    
    /**
     * Test style with base64 nonce
     *
     * @return void
     */
    public function testStyleNonceBase64(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'self\'; object-src \'none\'; style-src \'nonce-' . $nonce . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy('object-src', 'none');
        $csp->addNonce('style-src', $nonce);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testStyleNonceBase64()

    
    /**
     * Test script hash with base64 hash
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
     * Test script hash with hex hash
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
     * Test script hash sha384 with base64 hash
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
     * Test script hash 384 with hex hash
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
     * Test script hash sha384 with base64 hash
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
     * Test script hash 384 with hex hash
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

    
    
    
    
    
    
    /**
     * Test script with unsafe inline
     *
     * @return void
     */
//    public function testScriptUnsafeInline(): void
//    {
//        $expected = 'default-src \'none\'; script-src \'self\' \'unsafe-inline\';';
//        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
//        $csp->addDirectivePolicy('script-src', 'self');
//        $csp->addDirectivePolicy('script-src', 'unsafe-inline');
//        $actual = $csp->buildHeader();
//        $this->assertEquals($expected, $actual);
//    }//end testScriptUnsafeInline()

    
    /**
     * Test script with unsafe eval
     *
     * @return void
     */
//    public function testScriptUnsafeEval(): void
//    {
//        $expected = 'default-src \'none\'; script-src \'self\' \'unsafe-eval\';';
//        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
//        $csp->addDirectivePolicy('script-src', 'self');
//        $csp->addDirectivePolicy('script-src', 'unsafe-eval');
//        $actual = $csp->buildHeader();
//        $this->assertEquals($expected, $actual);
//    }//end testScriptUnsafeEval()

    
    /**
     * Test style with unsafe inline
     *
     * @return void
     */
//    public function testStyleUnsafeInline(): void
//    {
//        $expected = 'default-src \'none\'; style-src \'self\' \'unsafe-inline\';';
//        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
//        $csp->addDirectivePolicy('style-src', 'self');
//        $csp->addDirectivePolicy('style-src', 'unsafe-inline');
//        $actual = $csp->buildHeader();
//        $this->assertEquals($expected, $actual);
//    }//end testStyleUnsafeInline()


    /**
     * Try adding unsafe after adding nonce
     *
     * @return void
     */
//    public function testScriptAddNonceThenInline(): void
//    {
//        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
//        $expected = 'default-src \'none\'; script-src \'nonce-' . $nonce . '\';';
//        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
//        $csp->addNonce('script-src', $nonce);
//        $csp->addDirectivePolicy('script-src', 'unsafe-inline');
//        $actual = $csp->buildHeader();
//        $this->assertEquals($expected, $actual);
//    }//end testScriptAddNonceThenInline()

    
    /**
     * Try adding unsafe before adding nonce
     *
     * @return void
     */
//    public function testScriptAddInlineThenNonce(): void
//    {
//        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
//        $expected = 'default-src \'none\'; script-src \'nonce-' . $nonce . '\';';
//        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
//        $csp->addDirectivePolicy('script-src', 'unsafe-inline');
//        $csp->addNonce('script-src', $nonce);
//        $actual = $csp->buildHeader();
//        $this->assertEquals($expected, $actual);
//    }//end testScriptAddInlineThenNonce()
}//end class

?>