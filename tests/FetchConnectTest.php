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
final class FetchConnectTest extends TestCase
{
    /**
     * Tests header output when explicitly set to *
     *
     * @return void
     */
    public function testPolicyUnprotected(): void
    {
        $expected = 'default-src \'none\'; connect-src *;';
        $directive = 'connect-src';
        $policy = '*';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicyUnprotected()

  
    /**
     * Tests header output when explicitly set to 'self'
     *
     * @return void
     */
    public function testPolicySelf(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\';';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicySelf()

    
    /**
     * Tests header output when explicitly set to 'none'
     *
     * @return void
     */
    public function testPolicyNone(): void
    {
        $expected = 'default-src \'self\'; connect-src \'none\'; plugin-types image/svg+xml application/pdf;';
        $directive = 'connect-src';
        $policy = 'none';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicyNone()

    
    /**
     * Tests header output when explicitly set to 'https:'
     *
     * @return void
     */
    public function testPolicyHttps(): void
    {
        $expected = 'default-src \'none\'; connect-src https:;';
        $directive = 'connect-src';
        $policy = 'https:';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicyHttps()

    
    /**
     * Tests header output when explicitly set to 'self https:'
     *
     * @return void
     */
    public function testPolicySelfHttps(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\' https:;';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https:';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicySelfHttps()

    
    /**
     * Tests header output when explicitly set to 'self https:' then set to 'none'
     *
     * @return void
     */
    public function testPolicyResetToNone(): void
    {
        $expected = 'default-src \'self\'; connect-src \'none\'; plugin-types image/svg+xml application/pdf;';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https:';
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'none';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicyResetToNone()

    
    /**
     * Tests header output when explicitly set to 'self https:' then set to 'none'
     *
     * @return void
     */
    public function testPolicyResetToSelf(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\';';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https:';
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'self';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicyResetToSelf()

    
    /**
     * Tests header output when explicitly set to 'self example.org'
     *
     * @return void
     */
    public function testPolicySelfHostname(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\' example.org;';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'example.org';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicySelfHostname()

    
    /**
     * Tests header output when explicitly set to 'self example.org:443'
     *
     * @return void
     */
    public function testPolicySelfHostnamePort(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\' example.org:443;';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'example.org:443';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicySelfHostnamePort()

    
    /**
     * Tests header output when explicitly set to 'self https://example.org'
     *
     * @return void
     */
    public function testPolicySelfSchemeHostname(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\' https://example.org;';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https://example.org';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicySelfSchemeHostname()

    
    /**
     * Tests header output when explicitly set to 'self https://example.org:443'
     *
     * @return void
     */
    public function testPolicySelfSchemeHostnamePort(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\' https://example.org:443;';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https://example.org:443';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicySelfSchemeHostnamePort()

    
    /**
     * Tests header output when explicitly set to 'self *.example.org'
     *
     * @return void
     */
    public function testPolicySelfWildcardInHostname(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\' *.example.org;';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = '*.example.org';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicySelfWildcardInHostname()
    
    /**
     * Tests header output when explicitly set to 'self *.example.org:443'
     *
     * @return void
     */
    public function testPolicySelfWildcardInHostnameButNotInPort(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\' *.example.org:443;';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = '*.example.org:443';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicySelfWildcardInHostnameButNotInPort()

    
    /**
     * Tests header output when explicitly set to 'self *.example.org:*'
     *
     * @return void
     */
    public function testPolicySelfWildcardInHostnameAndInPort(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\' *.example.org:*;';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = '*.example.org:*';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicySelfWildcardInHostnameAndInPort()

    
    /**
     * Tests header output when explicitly set to 'self https://*.example.org:*'
     *
     * @return void
     */
    public function testPolicySelfSchemeWildcardInHostnameAndInPort(): void
    {
        $expected = 'default-src \'none\'; connect-src \'self\' https://*.example.org:*;';
        $directive = 'connect-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https://*.example.org:*';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testPolicySelfSchemeWildcardInHostnameAndInPort()
}//end class

?>