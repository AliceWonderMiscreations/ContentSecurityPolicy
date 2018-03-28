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
final class FetchDirectiveZzzChildSrcTest extends TestCase
{
    /**
     * Test child-src when both frame and worker same as default
     *
     * @return void
     */
    public function testChildSrcFrameWorkerSameAsDefault(): void
    {
        $expected = 'default-src \'self\'; object-src \'none\';';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy($policy);
        $csp->addFetchPolicy('object-src', 'none');
        $csp->addFetchPolicy('frame-src', $policy);
        $csp->addFetchPolicy('worker-src', $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testChildSrcFrameWorkerSameAsDefault()

    /**
     * Test child-src when both frame and worker same but different than default
     *
     * @return void
     */
    public function testChildSrcFrameWorkerSameButNotDefault(): void
    {
        $expected = 'default-src \'none\'; child-src \'self\'; frame-src \'self\'; worker-src \'self\';';
        $policy = 'self';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('frame-src', $policy);
        $csp->addFetchPolicy('worker-src', $policy);
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testChildSrcFrameWorkerSameButNotDefault()

    /**
     * Test child-src when frame and worker differ from each other and from self
     *
     * @return void
     */
    public function testChildSrcFrameAndWorkerAndDefaultAllDiffer(): void
    {
        $expected = 'default-src \'none\'; child-src https://www.example.org https://worker.example.org; frame-src https://www.example.org; worker-src https://worker.example.org;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('frame-src', 'https://www.example.org');
        $csp->addFetchPolicy('worker-src', 'https://worker.example.org');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testChildSrcFrameAndWorkerAndDefaultAllDiffer()

    /**
     * Test child-src when default self, frame url, worker none
     *
     * @return void
     */
    public function testChildSrcDefaultSelfFrameHostnameWorkerNone(): void
    {
        $expected = 'default-src \'self\'; child-src https://www.example.org; frame-src https://www.example.org; object-src \'none\'; worker-src \'none\';';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('self');
        $csp->addFetchPolicy('object-src', 'none');
        $csp->addFetchPolicy('frame-src', 'https://www.example.org');
        $csp->addFetchPolicy('worker-src', 'none');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testChildSrcDefaultSelfFrameHostnameWorkerNone()

    /**
     * Test child-src when default none, frame self, worker self url
     *
     * @return void
     */
    public function testChildSrcDefaultNoneFrameSelfWorkerSelfHostname(): void
    {
        $expected = 'default-src \'none\'; child-src \'self\' https://worker.example.org; frame-src \'self\'; worker-src \'self\' https://worker.example.org;';
        $csp = new \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy('none');
        $csp->addFetchPolicy('frame-src', 'self');
        $csp->addFetchPolicy('worker-src', 'self');
        $csp->addFetchPolicy('worker-src', 'https://worker.example.org');
        $actual = $csp->buildHeader();
        $this->assertEquals($expected, $actual);
    }//end testChildSrcDefaultNoneFrameSelfWorkerSelfHostname()
}//end class

?>