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
final class FetchDirectiveObjectSrcTest extends TestCase
{
    /**
     * Tests header output when explicitly set to *.
     *
     * @return void
     */
    public function testParameterWildcardForEverything(): void
    {
        $expected = 'default-src \'none\'; object-src *; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\'; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'self\'; object-src \'none\';';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src https:; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\' https:; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'self\'; object-src \'none\';';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\'; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\' example.org; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\' example.org:443; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\' https://example.org; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\' https://example.org:443; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\' *.example.org; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\' *.example.org:443; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\' *.example.org:*; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'none\'; object-src \'self\' https://*.example.org:*; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
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
        $expected = 'default-src \'self\' https://cdn.example.net; object-src \'self\' https://cdn.example.net https://*.elsewhere.com; plugin-types image/svg+xml application/pdf;';
        $directive = 'object-src';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self https://cdn.example.net');
        $csp->copyDefaultFetchPolicy($directive);
        $policy = 'https://*.elsewhere.com';
        $csp->addFetchPolicy($directive, $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testCopyDefaultAddHost()
}//end class

?>