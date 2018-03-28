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
final class FetchDirectiveWorkerSrcTest extends TestCase
{
    /**
     * Tests header output when explicitly set to *.
     *
     * @return void
     */
    public function testParameterWildcardForEverything(): void
    {
        $expected = 'default-src \'none\'; child-src *; frame-src \'none\'; worker-src *;';
        $directive = 'worker-src';
        $policy = '*';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParameterWildcardForEverything()

    /**
     * Tests header output when explicitly set to 'self'.
     *
     * @return void
     */
    public function testParameterSelf(): void
    {
        $expected = 'default-src \'none\'; child-src \'self\'; frame-src \'none\'; worker-src \'self\';';
        $directive = 'worker-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParameterSelf()

    /**
     * Tests header output when explicitly set to 'none'.
     *
     * @return void
     */
    public function testParameterNone(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'self\'; child-src \'none\'; frame-src \'self\'; worker-src \'none\'; plugin-types image/svg+xml application/pdf;';
        $directive = 'worker-src';
        $policy = 'none';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParameterNone()

    /**
     * Tests header output when explicitly set to 'https:'.
     *
     * @return void
     */
    public function testSchemeParamaterHttps(): void
    {
        $expected = 'default-src \'none\'; child-src https:; frame-src \'none\'; worker-src https:;';
        $directive = 'worker-src';
        $policy = 'https:';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testSchemeParamaterHttps()

    /**
     * Tests header output when explicitly set to 'self https:'.
     *
     * @return void
     */
    public function testParamatersSelfAndSchemeHttps(): void
    {
        $expected = 'default-src \'none\'; child-src \'self\' https:; frame-src \'none\'; worker-src \'self\' https:;';
        $directive = 'worker-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https:';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParamatersSelfAndSchemeHttps()

    /**
     * Tests header output when explicitly set to 'self https:' then set to 'none'.
     *
     * @return void
     */
    public function testResetParamatersToNone(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'self\'; child-src \'none\'; frame-src \'self\'; worker-src \'none\'; plugin-types image/svg+xml application/pdf;';
        $directive = 'worker-src';
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
     * Tests header output when explicitly set to 'self https:' then set to 'none'.
     *
     * @return void
     */
    public function testResetParametersToSelf(): void
    {
        $expected = 'default-src \'none\'; child-src \'self\'; frame-src \'none\'; worker-src \'self\';';
        $directive = 'worker-src';
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
     * Tests header output when explicitly set to 'self example.org'.
     *
     * @return void
     */
    public function testParamatersSelfAndHostname(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'none\'; child-src \'self\' example.org; frame-src \'none\'; worker-src \'self\' example.org;';
        $directive = 'worker-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'example.org';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParamatersSelfAndHostname()

    /**
     * Tests header output when explicitly set to 'self example.org:443'.
     *
     * @return void
     */
    public function testParamatersSelfAndHostnameWithPort(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'none\'; child-src \'self\' example.org:443; frame-src \'none\'; worker-src \'self\' example.org:443;';
        $directive = 'worker-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'example.org:443';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParamatersSelfAndHostnameWithPort()

    /**
     * Tests header output when explicitly set to 'self https://example.org'.
     *
     * @return void
     */
    public function testParametersSelfAndSchemeWithHostname(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'none\'; child-src \'self\' https://example.org; frame-src \'none\'; worker-src \'self\' https://example.org;';
        $directive = 'worker-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https://example.org';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfAndSchemeWithHostname()

    /**
     * Tests header output when explicitly set to 'self https://example.org:443'.
     *
     * @return void
     */
    public function testParametersSelfAndSchemeWithHostnameWithPort(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'none\'; child-src \'self\' https://example.org:443; frame-src \'none\'; worker-src \'self\' https://example.org:443;';
        $directive = 'worker-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https://example.org:443';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfAndSchemeWithHostnameWithPort()

    /**
     * Tests header output when explicitly set to 'self *.example.org'.
     *
     * @return void
     */
    public function testParametersSelfWithWildcardInHostname(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'none\'; child-src \'self\' *.example.org; frame-src \'none\'; worker-src \'self\' *.example.org;';
        $directive = 'worker-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = '*.example.org';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfWithWildcardInHostname()

    /**
     * Tests header output when explicitly set to 'self *.example.org:443'.
     *
     * @return void
     */
    public function testParametersSelfWithWildcardInHostnameWithPort(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'none\'; child-src \'self\' *.example.org:443; frame-src \'none\'; worker-src \'self\' *.example.org:443;';
        $directive = 'worker-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = '*.example.org:443';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfWithWildcardInHostnameWithPort()

    /**
     * Tests header output when explicitly set to 'self *.example.org:*'.
     *
     * @return void
     */
    public function testParametersSelfWithWildcardInHostnameAndInPort(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'none\'; child-src \'self\' *.example.org:*; frame-src \'none\'; worker-src \'self\' *.example.org:*;';
        $directive = 'worker-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = '*.example.org:*';
        @$csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfWithWildcardInHostnameAndInPort()

    /**
     * Tests header output when explicitly set to 'self https://*.example.org:*'.
     *
     * @return void
     */
    public function testParametersSelfWithSchemeAndWildcardInHostnameAndInPort(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'none\'; child-src \'self\' https://*.example.org:*; frame-src \'none\'; worker-src \'self\' https://*.example.org:*;';
        $directive = 'worker-src';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy($directive, $policy);
        $policy = 'https://*.example.org:*';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testParametersSelfWithSchemeAndWildcardInHostnameAndInPort()

    /**
     * Tests header output when copying default and appending.
     *
     * @return void
     */
    public function testCopyDefaultAddHost(): void
    {
        // @codingStandardsIgnoreLine
        $expected = 'default-src \'self\' https://cdn.example.net; child-src \'self\' https://cdn.example.net https://*.elsewhere.com; frame-src \'self\' https://cdn.example.net; worker-src \'self\' https://cdn.example.net https://*.elsewhere.com; plugin-types image/svg+xml application/pdf;';
        $directive = 'worker-src';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self https://cdn.example.net');
        $csp->copyDefaultFetchPolicy($directive);
        $policy = 'https://*.elsewhere.com';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testCopyDefaultAddHost()
}//end class

?>