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
        $expected = 'default-src \'none\'; script-src \'self\'; connect-src \'self\'; img-src \'self\'; style-src \'self\'; media-src \'self\';';
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
     * for child-src.
     *
     * @return void
     */
    public function testDefaultNoneChildSelf(): void
    {
        $expected = 'default-src \'none\'; child-src \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addDirectivePolicy('child-src', 'self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testDefaultNoneChildSelf()

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
}//end class

