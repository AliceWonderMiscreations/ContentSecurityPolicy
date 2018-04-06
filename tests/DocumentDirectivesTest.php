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
final class DocumentDirectivesTest extends TestCase
{
    /**
     * Test header output setting base-uri to self with setBaseUriPolicy
     *
     * @return void
     */
    public function testBaseUriSelfViaSetBaseUriPolicy(): void
    {
        $expected = 'default-src \'none\'; base-uri \'self\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->SetBaseUriPolicy('self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test header output setting base-uri to none with setBaseUriPolicy
     *
     * @return void
     */
    public function testBaseUriNoneViaSetBaseUriPolicy(): void
    {
        $expected = 'default-src \'none\'; base-uri \'none\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->SetBaseUriPolicy('none');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test header output setting base-uri to host with setBaseUriPolicy
     *
     * @return void
     */
    public function testBaseUriHostViaSetBaseUriPolicy(): void
    {
        $expected = 'default-src \'none\'; base-uri https://example.org;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->SetBaseUriPolicy('https://example.org');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test header output with default pluginTypes
     *
     * @return void
     */
    public function testDefaultPluginTypes(): void
    {
        $expected = 'default-src \'self\'; plugin-types image/svg+xml application/pdf;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test header output with pluginTypes set to text/plain
     *
     * @return void
     */
    public function testPluginTypesTextPlain(): void
    {
        $expected = 'default-src \'self\'; plugin-types text/plain;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->setPluginTypesPolicy('text/plain');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test header output with pluginTypes set to application/x-shockwave-flash
     *
     * @return void
     */
    public function testPluginTypesFlash(): void
    {
        $expected = 'default-src \'self\'; plugin-types application/x-shockwave-flash;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->setPluginTypesPolicy('application/x-shockwave-flash');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test header output setting sanbox to allow-pointer-lock
     *
     * @return void
     */
    public function testSandboxAllowPointerLock(): void
    {
        $expected = 'default-src \'none\'; sandbox allow-pointer-lock;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->setSandboxPolicy('allow-pointer-lock');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
    
    /**
     * Test header output setting sanbox to allow-pointer-lock and allow-scripts
     *
     * @return void
     */
    public function testSandboxAllowPointerLockAndAllowScripts(): void
    {
        $expected = 'default-src \'none\'; sandbox allow-pointer-lock allow-scripts;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->setSandboxPolicy('allow-pointer-lock');
        $csp->setSandboxPolicy('allow-scripts');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }
}






















?>