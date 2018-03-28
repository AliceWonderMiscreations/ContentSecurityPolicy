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
final class FetchDirectiveScriptSrcTest extends TestCase
{
    /**
     * Tests header output when explicitly set to *.
     *
     * @return void
     */
    public function testParameterWildcardForEverything(): void
    {
        $expected = 'default-src \'none\'; script-src *;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\';';
        $directive = 'script-src';
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
        $expected = 'default-src \'self\'; script-src \'none\'; plugin-types image/svg+xml application/pdf;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src https:;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\' https:;';
        $directive = 'script-src';
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
        $expected = 'default-src \'self\'; script-src \'none\'; plugin-types image/svg+xml application/pdf;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\';';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\' example.org;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\' example.org:443;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\' https://example.org;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\' https://example.org:443;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\' *.example.org;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\' *.example.org:443;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\' *.example.org:*;';
        $directive = 'script-src';
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
        $expected = 'default-src \'none\'; script-src \'self\' https://*.example.org:*;';
        $directive = 'script-src';
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
        $expected = 'default-src \'self\' https://cdn.example.net; script-src \'self\' https://cdn.example.net https://*.elsewhere.com; plugin-types image/svg+xml application/pdf;';
        $directive = 'script-src';
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
    public function testScriptSrcUnsafeInline(): void
    {
        $expected = 'default-src \'none\'; script-src \'unsafe-inline\';';
        $directive = 'script-src';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('script-src', 'unsafe-inline');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptSrcUnsafeInline()

    /**
     * Tests header output with unsafe-inline.
     *
     * @return void
     */
    public function testScriptSrcUnsafeEval(): void
    {
        $expected = 'default-src \'none\'; script-src \'unsafe-eval\';';
        $directive = 'script-src';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        @$csp->addFetchPolicy('script-src', 'unsafe-eval');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptSrcUnsafeEval()

    /**
     * Tests header output with hash via addFetchPolicy.
     *
     * @return void
     */
    public function testSrcAddHashViaAddFetchPolicy(): void
    {
        $raw = random_bytes(32);
        $hex = bin2hex($raw);
        $b64 = base64_encode($raw);
        $expected = 'default-src \'none\'; script-src \'sha256-' . $b64 . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('script-src', 'sha256-' . $hex);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
        // reset for base64 test
        $csp->addFetchPolicy('script-src', 'none');
        $actual = $csp->buildHeader();
        $this->assertEquals('default-src \'none\';', $actual);
        // base64 test
        $csp->addFetchPolicy('script-src', 'sha256-' . $b64);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testSrcAddHashViaAddFetchPolicy()

    /**
     * Tests header output with hash via addScriptHash.
     *
     * @return void
     */
    public function testSrcAddHashViaAddScriptHash(): void
    {
        $raw = random_bytes(32);
        $hex = bin2hex($raw);
        $b64 = base64_encode($raw);
        $expected = 'default-src \'none\'; script-src \'sha256-' . $b64 . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addScriptHash('sha256', $hex);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
        // reset for base64 test
        $csp->addFetchPolicy('script-src', 'none');
        $actual = $csp->buildHeader();
        $this->assertEquals('default-src \'none\';', $actual);
        // base64 test
        $csp->addScriptHash('sha256', $b64);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testSrcAddHashViaAddScriptHash()

    /**
     * Tests header output with nonce via addFetchPolicy.
     *
     * @return void
     */
    public function testScrAddNonceViaAddFetchPolicy(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'none\'; script-src \'nonce-' . $nonce . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('script-src', 'nonce-' . $nonce);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScrAddNonceViaAddFetchPolicy()

    /**
     * Tests header output with nonce via addNonce.
     *
     * @return void
     */
    public function testScrAddNonceViaAddNonce(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'none\'; script-src \'nonce-' . $nonce . '\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addNonce('script-src', $nonce);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScrAddNonceViaAddNonce()

    /**
     * Tests header output unsafe-inline then nonce.
     * Nonce should take precedence.
     *
     * @return void
     */
    public function testScriptSrcUnsafeInlineThenNonce(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'none\'; script-src \'nonce-' . $nonce . '\';';
        $directive = 'script-src';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('script-src', 'unsafe-inline');
        $csp->addNonce('script-src', $nonce);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptSrcUnsafeInlineThenNonce()

    /**
     * Tests header output nonce then unsafe-inline.
     * Nonce should take precedence.
     *
     * @return void
     */
    public function testScriptSrcNonceThenUnsafeInline(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $expected = 'default-src \'none\'; script-src \'nonce-' . $nonce . '\';';
        $directive = 'script-src';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addNonce('script-src', $nonce);
        $csp->addFetchPolicy('script-src', 'unsafe-inline');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptSrcNonceThenUnsafeInline()

    /**
     * Set the strict-dynamic parameter in script-src.
     *
     * @return void
     */
    public function testScriptSetStrictDynamic(): void
    {
        $nonce = \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy::generateNonce();
        $hash = hash('sha256', $nonce, true);
        $b64 = base64_encode($hash);
        // first test, should fail to set without a nonce or hash set
        $expected = 'default-src \'none\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('script-src', 'strict-dynamic');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
        // second test - should add the parameter if nonce present
        $expected = 'default-src \'none\'; script-src \'nonce-' . $nonce . '\' \'strict-dynamic\';';
        $csp->addNonce('script-src', $nonce);
        $csp->addFetchPolicy('script-src', 'strict-dynamic');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
        // wipe the policy for third test
        $expected = 'default-src \'none\';';
        $csp->addFetchPolicy('script-src', '\'none\'');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
        // third test - should add the parameter if hash present
        $expected = 'default-src \'none\'; script-src \'sha256-' . $b64 . '\' \'strict-dynamic\';';
        $csp->addScriptHash('sha256', $b64);
        $csp->addFetchPolicy('script-src', 'strict-dynamic');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testScriptSetStrictDynamic()

    /**
     * Test header output with report-sample.
     *
     * @return void
     */
    public function testScriptReportSample(): void
    {
        // first test - should only apply if reporting enabled
        $expected = 'default-src \'none\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('script-src', 'report-sample');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
        // second test - add a report uri
        //  TODO FIXME function to do so not yet written
        // wipe for third test
        $expected = 'default-src \'none\';';
        $csp->addFetchPolicy('script-src', '\'none\'');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
        // third test - add a report-to
        //  TODO FIXME function to do so not yet written
    }//end testScriptReportSample()
}//end class

?>