<?php

use PHPUnit\Framework\TestCase;

final class ContentSecurityPolicyTest extends TestCase
{
	public function testDummyCase(): void
        {
            $a = 'foo';
            $b = 'foo';
            $this->assertEquals($a,$b);
        }
}
