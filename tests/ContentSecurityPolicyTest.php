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
     * Tests header output when 'self' parameter specified to constructor and 'none' specified
     * for object-src. Should suppress output of plugin-types.
     *
     * @return void
     */
    public function testDefaultSelfObjectNone(): void
    {
        $expected = 'default-src \'self\'; object-src \'none\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addDirectivePolicy('object-src', 'none');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultSelfObjectNone()

    /**
     * Tests header output when 'self' parameter specified to constructor and 'self' specified
     * for object-src. Should display output of plugin-types but suppress object-src since it
     * is identical to default-src.
     *
     * @return void
     */
    public function testDefaultSelfObjectSelf(): void
    {
        $expected = 'default-src \'self\'; plugin-types image/svg+xml application/pdf;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addDirectivePolicy('object-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultSelfObjectSelf()

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
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for script-src.
     *
     * @return void
     */
    public function testDefaultNoneScriptSelf(): void
    {
        $expected = 'default-src \'none\'; script-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('script-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneScriptSelf()

    /**
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for style-src.
     *
     * @return void
     */
    public function testDefaultNoneStyleSelf(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('style-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneStyleSelf()

    /**
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for img-src.
     *
     * @return void
     */
    public function testDefaultNoneImgSelf(): void
    {
        $expected = 'default-src \'none\'; img-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('img-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneImgSelf()

    /**
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for connect-src.
     *
     * @return void
     */
    public function testDefaultNoneConnectSelf(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('connect-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneConnectSelf()

    /**
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for font-src.
     *
     * @return void
     */
    public function testDefaultNoneFontSelf(): void
    {
        $expected = 'default-src \'none\'; font-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('font-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneFontSelf()
    
    /**
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for manifest-src.
     *
     * @return void
     */
    public function testDefaultNoneManifestSelf(): void
    {
        $expected = 'default-src \'none\'; manifest-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('manifest-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneFontSelf()

    /**
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for media-src.
     *
     * @return void
     */
    public function testDefaultNoneMediaSelf(): void
    {
        $expected = 'default-src \'none\'; media-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('media-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneMediaSelf()

    /**
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for frame-src.
     *
     * @return void
     */
    public function testDefaultNoneFrameSelf(): void
    {
        $expected = 'default-src \'none\'; frame-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('frame-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneFrameSelf()
    
    /**
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for frame-src.
     *
     * @return void
     */
    public function testDefaultNoneWorkerSelf(): void
    {
        $expected = 'default-src \'none\'; worker-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('worker-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneWorkerSelf()

    /**
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for form-action.
     *
     * @return void
     */
    public function testDefaultNoneFormActionSelf(): void
    {
        $expected = 'default-src \'none\'; form-action \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('form-action', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneFormActionSelf()

    /**
     * Tests header output when 'none' parameter specified to constructor and 'self' specified
     * for frame-ancestors.
     *
     * @return void
     */
    public function testDefaultNoneFrameAncestorsSelf(): void
    {
        $expected = 'default-src \'none\'; frame-ancestors \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('frame-ancestors', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneFrameAncestorsSelf()

    /**
     * Tests generation of nonce. Should be 8-byte when argument null, 8-byte when argument
     * is 6, 12 byte when argument is 12. (2 hex = 1 byte)
     *
     * @return void
     */
    public function testGenerateNonce(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $raw = base64_decode($nonce);
        $hex = bin2hex($raw);
        $len = strlen($hex);
        $this->assertEquals(16, $len);
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce(6);
        $raw = base64_decode($nonce);
        $hex = bin2hex($raw);
        $len = strlen($hex);
        $this->assertEquals(16, $len);
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce(12);
        $raw = base64_decode($nonce);
        $hex = bin2hex($raw);
        $len = strlen($hex);
        $this->assertEquals(24, $len);
    }//end testGenerateNonce()
    
    /**
     * Test script with base64 nonce
     *
     * @return null
     */
    public function testScriptNonceBase64(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'nonce-' . $nonce . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addDirectivePolicy('object-src', 'none');
        $csp->addNonce('script-src', $nonce);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test style with base64 nonce
     *
     * @return null
     */
    public function testStyleNonceBase64(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'self\'; object-src \'none\'; style-src \'nonce-' . $nonce . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addDirectivePolicy('object-src', 'none');
        $csp->addNonce('style-src', $nonce);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test script hash with base64 hash
     *
     * @return null
     */
    public function testScriptHashSha256Base64(): void
    {
        $raw = random_bytes(32);
        $hash = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha256-' . $hash . '\';';
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addDirectivePolicy('object-src', 'none');
        $csp->addInlineScriptHash('sha256', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test script hash with hex hash
     *
     * @return null
     */
    public function testScriptHashSha256Hex(): void
    {
        $raw = random_bytes(32);
        $hash64 = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha256-' . $hash64 . '\';';
        $hash = bin2hex($raw);
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addDirectivePolicy('object-src', 'none');
        $csp->addInlineScriptHash('sha256', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test script hash sha384 with base64 hash
     *
     * @return null
     */
    public function testScriptHashSha384Base64(): void
    {
        $raw = random_bytes(48);
        $hash = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha384-' . $hash . '\';';
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addDirectivePolicy('object-src', 'none');
        $csp->addInlineScriptHash('sha384', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test script hash 384 with hex hash
     *
     * @return null
     */
    public function testScriptHashSha384Hex(): void
    {
        $raw = random_bytes(48);
        $hash64 = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha384-' . $hash64 . '\';';
        $hash = bin2hex($raw);
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addDirectivePolicy('object-src', 'none');
        $csp->addInlineScriptHash('sha384', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test script hash sha384 with base64 hash
     *
     * @return null
     */
    public function testScriptHashSha512Base64(): void
    {
        $raw = random_bytes(64);
        $hash = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha512-' . $hash . '\';';
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addDirectivePolicy('object-src', 'none');
        $csp->addInlineScriptHash('sha512', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test script hash 384 with hex hash
     *
     * @return null
     */
    public function testScriptHashSha512Hex(): void
    {
        $raw = random_bytes(64);
        $hash64 = base64_encode($raw);
        $expected = 'default-src \'self\'; object-src \'none\'; script-src \'sha512-' . $hash64 . '\';';
        $hash = bin2hex($raw);
        
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addDirectivePolicy('object-src', 'none');
        $csp->addInlineScriptHash('sha512', $hash);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    
    
    
    
    
    /**
     * Test script with unsafe inline
     *
     * @return null
     */
    public function testScriptUnsafeInline(): void
    {
        $expected = 'default-src \'none\'; script-src \'self\' \'unsafe-inline\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('script-src', 'self');
        $csp->addDirectivePolicy('script-src', 'unsafe-inline');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test script with unsafe eval
     *
     * @return null
     */
    public function testScriptUnsafeEval(): void
    {
        $expected = 'default-src \'none\'; script-src \'self\' \'unsafe-eval\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('script-src', 'self');
        $csp->addDirectivePolicy('script-src', 'unsafe-eval');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test style with unsafe inline
     *
     * @return null
     */
    public function testStyleUnsafeInline(): void
    {
        $expected = 'default-src \'none\'; style-src \'self\' \'unsafe-inline\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('style-src', 'self');
        $csp->addDirectivePolicy('style-src', 'unsafe-inline');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
}//end class

?>