<?php
declare(strict_types=1);

/**
 * An implementation of Content Security Policy.
 *
 * @package AWonderPHP/ContentSecurityPolicy
 * @author  Alice Wonder <paypal@domblogger.net>
 * @license https://opensource.org/licenses/MIT MIT
 * @link    https://github.com/AliceWonderMiscreations/ContentSecurityPolicy
 */

namespace AWonderPHP\ContentSecurityPolicy;

/**
 * An implementation of Content Security Policy.
 *
 * Based on the specification at
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy but is
 * bit more restrictive with the nonce, where it requires the nonce be base64 encoded or hex encoded string.
 *
 */
class ContentSecurityPolicy
{
    /**
     * Valid CSP Fetch Directives excluding default-src.
     *
     * @var array
     */
    protected $fetchDirectives = array(
        'connect-src',
        'font-src',
        'frame-src',
        'img-src',
        'manifest-src',
        'media-src',
        'object-src',
        'script-src',
        'style-src',
        'worker-src'
    );

    /**
     * Experimental CSP Directives not yet widely supported.
     *
     * @var array
     */
    protected $experimentalDirectives = array(
        'disown-opener',
        'navigation-to',
        'report-to'
    );

    /* Fetch Directives */

    /**
     * Serves as a fallback for the other fetch directives.
     *
     * @var array
     */
    protected $defaultSrc = array('\'none\'');

    /**
     * Restricts the URLs which can be loaded using script interfaces.
     *
     * @var array
     */
    protected $connectSrc = array();

    /**
     * Specifies valid sources for fonts loaded using @font-face.
     *
     * @var array
     */
    protected $fontSrc = array();

    /**
     * Specifies valid sources for nested browsing contexts loading using elements such as
     * <frame> and <iframe>.
     *
     * @var array
     */
    protected $frameSrc = array();

    /**
     * Specifies valid sources of images and favicons.
     *
     * @var array
     */
    protected $imgSrc = array();

    /**
     * Specifies valid sources of application manifest files.
     *
     * @var array
     */
    protected $manifestSrc = array();

    /**
     * Specifies valid sources for loading media using the <audio> , <video> and <track>
     * elements.
     *
     * @var array
     */
    protected $mediaSrc = array();

    /**
     * Specifies valid sources for the <object>, <embed>, and <applet> elements.
     *
     * @var array
     */
    protected $objectSrc = array();

    /**
     * Specifies valid sources for JavaScript.
     *
     * @var array
     */
    protected $scriptSrc = array();

    /**
     * Specifies valid sources for stylesheets.
     *
     * @var array
     */
    protected $styleSrc = array();

    /**
     * Specifies valid sources for Worker, SharedWorker, or ServiceWorker scripts.
     *
     * @var array
     */
    protected $workerSrc = array();

    /* Document Directives */

    /**
     * Restricts the URLs which can be used in a document's <base> element.
     *
     * @var array
     */
    protected $baseUri = array();

    /**
     * Restricts the set of plugins that can be embedded into a document by limiting the types
     * of resources which can be loaded.
     *
     * The arguments must be valid MIME types of the form <type>/<subtype> e.g:
     * 'application/x-shockwave-flash'.
     *
     * In this implementation, image/svg+xml and application/pdf are allowed by default.
     *
     * @var array
     */
    protected $pluginTypes = array('image/svg+xml', 'application/pdf');

    /**
     * Enables a sandbox for the requested resource similar to the <iframe> sandbox attribute.
     *
     * @var array
     */
    protected $sandbox = array();

    /**
     * Allowed sandbox values
     *
     * @var array
     */
    protected $validSandboxValues = array(
        'allow-forms',
        'allow-modals',
        'allow-orientation-lock',
        'allow-pointer-lock',
        'allow-popups',
        'allow-popups-to-escape-sandbox',
        'allow-presentation',
        'allow-same-origin',
        'allow-scripts',
        'allow-top-navigation'
        );

    /* Navigation Directives */

    /**
     * Restricts the URLs which can be used as the target of a form submissions from a given
     * context.
     *
     * @var array
     */
    protected $formAction = array();

    /**
     * Specifies valid parents that may embed a page using <frame>, <iframe>, <object>,
     * <embed>, or <applet>.
     *
     * @var array
     */
    protected $frameAncestors = array();

    /* Reporting Directives */

    /**
     * Instructs the user agent to report attempts to violate the Content Security Policy.
     * These violation reports consist of JSON documents sent via an HTTP POST request to the
     * specified URI.
     *
     * This directive will likely be replaced by the experimental report-to directive
     *
     * @var null|string
     */
    protected $reportUri = null;

    /**
     * Changes Content-Security-Policy header to Content-Security-Policy-Report-Only so that
     * the resource violation is reported but is not actually blocked.
     *
     * @var bool
     */
    protected $reportOnly = false;

    /**
     * Adjust the policy to add single upquote where needed.
     *
     * @param string $policy The policy string to adjust.
     *
     * @return string
     */
    protected function adjustPolicy(string $policy): string
    {
        $policy = trim($policy);
        $s = array('/^\'/', '/\'$/');
        $r = array('', '');
        $policy = preg_replace($s, $r, $policy);
        $test = strtolower($policy);
        switch ($test) {
            case 'none':
                $policy = '\'none\'';
                break;
            case 'self':
                $policy = '\'self\'';
                break;
            case 'unsafe-inline':
                $policy = '\'unsafe-inline\'';
                break;
            case 'unsafe-eval':
                $policy = '\'unsafe-eval\'';
                break;
            case 'strict-dynamic':
                $policy = '\'strict-dynamic\'';
                break;
            case 'report-sample':
                $policy = '\'report-sample\'';
                break;
        }
        return $policy;
    }//end adjustPolicy()

    /**
     * Adds unsafe-inline or unsafe-eval to script/style directive.
     *
     * @param string $directive The directive to be defined.
     * @param string $unsafe    The unsafe policy.
     *
     * @return bool True on success, False on failure.
     */
    protected function addUnsafe(string $directive, string $unsafe): bool
    {
        if (! in_array($unsafe, array('\'unsafe-inline\'', '\'unsafe-eval\''))) {
            return false;
        }
        switch ($unsafe) {
            case '\'unsafe-inline\'':
                if ($directive === 'script-src') {
                    foreach ($this->scriptSrc as $policy) {
                        $test = substr($policy, 0, 7);
                        if ($test === '\'nonce-') {
                            return true;
                        }
                    }
                    $this->scriptSrc[] = '\'unsafe-inline\'';
                    return true;
                }
                if ($directive === 'style-src') {
                    foreach ($this->styleSrc as $policy) {
                        $test = substr($policy, 0, 7);
                        if ($test === '\'nonce-') {
                            return true;
                        }
                    }
                    $this->styleSrc[] = '\'unsafe-inline\'';
                    return true;
                }
                break;
            case '\'unsafe-eval\'':
                if ($directive === 'script-src') {
                    $warning = 'It is not safe to set the \'unsafe-eval\' parameter. ';
                    $warning .= 'Please fix your JavaScript so this is no longer needed.';
                    trigger_error($warning, E_USER_NOTICE);
                    $this->scriptSrc[] = '\'unsafe-eval\'';
                    return true;
                }
        }
        return false;
    }//end addUnsafe()

    /**
     * Generates a child-src directive that is nutshell a union between frame-src and worker-src
     * This is produce a compatibility directive for CSP level 2 clients.
     *
     * @return array The directive parameters.
     */
    protected function generateChildFetchDirective(): array
    {
        $childSrc = array();
        $frameCount = count($this->frameSrc);
        $workerCount = count($this->workerSrc);
        if (($frameCount + $workerCount) === 0) {
            return array();
        }
        if ($frameCount === 0) {
            $childSrc = $this->workerSrc;
        }
        if ($workerCount === 0) {
            $childSrc = $this->frameSrc;
        }
        if ($this->frameSrc === $this->workerSrc) {
            $childSrc = $this->frameSrc;
        }
        if (count($childSrc) > 0) {
            return $childSrc;
        }
        $scheme = array();
        $otherKeyword = array();
        $host = array();
        foreach ($this->frameSrc as $param) {
            $a = 0;
            if ($param === '\'none\'') {
                $a++;
            }
            if ($a === 0) {
                if ($param === '\'self\'') {
                    if (! in_array($param, $childSrc)) {
                        $childSrc[] = $param;
                    }
                    $a++;
                }
            }
            if ($a === 0) {
                $test = substr($param, -1);
                if ($test === ':') {
                    if (! in_array($param, $scheme)) {
                        $scheme[] = $param;
                    }
                    $a++;
                }
            }
            if ($a === 0) {
                $test = substr($param, -1);
                if ($test === '\'') {
                    if (! in_array($param, $otherKeyword)) {
                        $otherKeyword[] = $param;
                    }
                    $a++;
                }
            }
            if ($a === 0) {
                $n = substr_count($param, '.');
                if ($n > 0) {
                    if (! in_array($param, $host)) {
                        $host[] = $param;
                    }
                    $a++;
                }
            }
        }
        foreach ($this->workerSrc as $param) {
            $a = 0;
            if ($param === '\'none\'') {
                $a++;
            }
            if ($a === 0) {
                if ($param === '\'self\'') {
                    if (! in_array($param, $childSrc)) {
                        $childSrc[] = $param;
                    }
                    $a++;
                }
            }
            if ($a === 0) {
                $test = substr($param, -1);
                if ($test === ':') {
                    if (! in_array($param, $scheme)) {
                        $scheme[] = $param;
                    }
                    $a++;
                }
            }
            if ($a === 0) {
                $test = substr($param, -1);
                if ($test === '\'') {
                    if (! in_array($param, $otherKeyword)) {
                        $otherKeyword[] = $param;
                    }
                    $a++;
                }
            }
            if ($a === 0) {
                $n = substr_count($param, '.');
                if ($n > 0) {
                    if (! in_array($param, $host)) {
                        $host[] = $param;
                    }
                    $a++;
                }
            }
        }
        foreach ($scheme as $param) {
            if (! in_array($param, $childSrc)) {
                $childSrc[] = $param;
            }
        }
        foreach ($otherKeyword as $param) {
            if (! in_array($param, $childSrc)) {
                $childSrc[] = $param;
            }
        }
        foreach ($scheme as $param) {
            if (! in_array($param, $childSrc)) {
                $childSrc[] = $param;
            }
        }
        foreach ($host as $param) {
            if (! in_array($param, $childSrc)) {
                $childSrc[] = $param;
            }
        }
        return $childSrc;
    }//end generateChildFetchDirective()

    /**
     * Determines if the array is set to 'none'.
     *
     * @param array $arr The array to check.
     *
     * @return bool True if set to 'none', False if not.
     */
    protected function checkForNone(array $arr): bool
    {
        if (isset($arr[0])) {
            if ($arr[0] === '\'none\'') {
                return true;
            }
        }
        return false;
    }//end checkForNone()

    /**
     * Determines whether or not object tags are allowed.
     *
     * @return bool True if allowed, False if not.
     */
    protected function objectsAllowed(): bool
    {
        if (count($this->objectSrc) > 0) {
            if ($this->objectSrc[0] === '\'none\'') {
                return false;
            }
            return true;
        }
        if ($this->defaultSrc[0] === '\'none\'') {
            return false;
        }
        if ($this->defaultSrc[0] === '\'self\'') {
            return true;
        }
        foreach ($this->defaultSrc as $param) {
            $test = substr($param, 0, 1);
            if ($test !== '\'') {
                return true;
            }
        }
        return false;
    }//end objectsAllowed()

    /**
     * Adds a policy to a directive or sets it if set to 'none'.
     *
     * @param string $directive The CSP policy directive.
     * @param string $policy    The CSP policy parameter.
     *
     * @return bool
     */
    protected function setPolicyParameter(string $directive, string $policy)
    {
        switch ($directive) {
            case 'default-src':
                if ($this->checkForNone($this->defaultSrc)) {
                    $this->defaultSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->defaultSrc)) {
                        $this->defaultSrc[] = $policy;
                    }
                }
                break;
            case 'connect-src':
                if ($this->checkForNone($this->connectSrc)) {
                    $this->connectSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->connectSrc)) {
                        $this->connectSrc[] = $policy;
                    }
                }
                break;
            case 'font-src':
                if ($this->checkForNone($this->fontSrc)) {
                    $this->fontSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->fontSrc)) {
                        $this->fontSrc[] = $policy;
                    }
                }
                break;
            case 'frame-src':
                if ($this->checkForNone($this->frameSrc)) {
                    $this->frameSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->frameSrc)) {
                        $this->frameSrc[] = $policy;
                    }
                }
                break;
            case 'img-src':
                if ($this->checkForNone($this->imgSrc)) {
                    $this->imgSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->imgSrc)) {
                        $this->imgSrc[] = $policy;
                    }
                }
                break;
            case 'manifest-src':
                if ($this->checkForNone($this->manifestSrc)) {
                    $this->manifestSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->manifestSrc)) {
                        $this->manifestSrc[] = $policy;
                    }
                }
                break;
            case 'media-src':
                if ($this->checkForNone($this->mediaSrc)) {
                    $this->mediaSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->mediaSrc)) {
                        $this->mediaSrc[] = $policy;
                    }
                }
                break;
            case 'object-src':
                if ($this->checkForNone($this->objectSrc)) {
                    $this->objectSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->objectSrc)) {
                        $this->objectSrc[] = $policy;
                    }
                }
                break;
            case 'script-src':
                if ($this->checkForNone($this->scriptSrc)) {
                    $this->scriptSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->scriptSrc)) {
                        $this->scriptSrc[] = $policy;
                    }
                }
                break;
            case 'style-src':
                if ($this->checkForNone($this->styleSrc)) {
                    $this->styleSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->styleSrc)) {
                        $this->styleSrc[] = $policy;
                    }
                }
                break;
            case 'worker-src':
                if ($this->checkForNone($this->workerSrc)) {
                    $this->workerSrc = array($policy);
                } else {
                    if (! in_array($policy, $this->workerSrc)) {
                        $this->workerSrc[] = $policy;
                    }
                }
                break;
            default:
                return false;
                break;
        }
        return true;
    }//end setPolicyParameter()

    /**
     * Defines the policy to the specified policy keyword. This is for
     * keywords where the keyword implies first or only policy for directive.
     *
     * @param string $directive  The directive to be defined.
     * @param string $keyword    The policy keyword.
     *
     * @return bool
     */
    protected function addPolicyKeyword(string $directive, string $keyword): bool
    {
        if (! in_array($keyword, array('\'self\'', '\'none\''))) {
            return false;
        }
        switch ($directive) {
            case 'default-src':
                $this->defaultSrc = array($keyword);
                break;
            case 'connect-src':
                $this->connectSrc = array($keyword);
                break;
            case 'font-src':
                $this->fontSrc = array($keyword);
                break;
            case 'frame-src':
                $this->frameSrc = array($keyword);
                break;
            case 'img-src':
                $this->imgSrc = array($keyword);
                break;
            case 'manifest-src':
                $this->manifestSrc = array($keyword);
                break;
            case 'media-src':
                $this->mediaSrc = array($keyword);
                break;
            case 'object-src':
                $this->objectSrc = array($keyword);
                break;
            case 'script-src':
                $this->scriptSrc = array($keyword);
                break;
            case 'style-src':
                $this->styleSrc = array($keyword);
                break;
            case 'worker-src':
                $this->workerSrc = array($keyword);
                break;
            case 'form-action':
                $this->formAction = array($keyword);
                break;
            case 'frame-ancestors':
                $this->frameAncestors = array($keyword);
                break;
            default:
                return false;
        }
        return true;
    }//end addPolicyKeyword()

    /**
     * Verifies that we have a valid nonce.
     *
     * @param string $nonce the nonce to test.
     *
     * @return bool True when valid, False when invalid.
     */
    protected function validateNonce(string $nonce): bool
    {
        if (base64_encode(base64_decode($nonce, true)) !== $nonce) {
            return false;
        }
        if (ctype_xdigit($nonce)) {
            return false;
        }
        $len = strlen($nonce);
        if ($len < 24) {
            return false;
        }
        return true;
    }//end validateNonce()

    /**
     * Adds script hash. Throws exception if invalid.
     *
     * @param string $algo The hash algorithm.
     * @param string $hash The hash.
     *
     * @return bool
     */
    public function addScriptHash(string $algo, string $hash): bool
    {
        $algo = trim(strtolower($algo));
        if (! in_array($algo, array('sha256', 'sha384', 'sha512'))) {
            throw InvalidArgumentException::badAlgo();
        }
        if (ctype_xdigit($hash)) {
            $raw = hex2bin($hash);
            $hash = base64_encode($raw);
        }
        if (base64_encode(base64_decode($hash)) !== $hash) {
            throw InvalidArgumentException::badHash();
        }
        switch ($algo) {
            case 'sha384':
                $hashLength = 64;
                break;
            case 'sha512':
                $hashLength = 88;
                break;
            default:
                $hashLength = 44;
                break;
        }
        if (strlen($hash) !== $hashLength) {
            throw InvalidArgumentException::badHash();
        }
        $policy = '\'' . $algo . '-' . $hash . '\'';
        if (count($this->scriptSrc) > 0) {
            if ($this->scriptSrc[0] === '\'none\'') {
                $this->scriptSrc[0] = $policy;
                return true;
            }
        }
        $this->scriptSrc[] = $policy;
        return true;
    }//end addScriptHash()

    /**
     * Adds style hash. Throws exception if invalid.
     *
     * @param string $algo The hash algorithm.
     * @param string $hash The hash.
     *
     * @return bool
     */
    public function addStyleHash(string $algo, string $hash): bool
    {
        $algo = trim(strtolower($algo));
        if (! in_array($algo, array('sha256', 'sha384', 'sha512'))) {
            throw InvalidArgumentException::badAlgo();
        }
        if (ctype_xdigit($hash)) {
            $raw = hex2bin($hash);
            $hash = base64_encode($raw);
        }
        if (base64_encode(base64_decode($hash)) !== $hash) {
            throw InvalidArgumentException::badHash();
        }
        switch ($algo) {
            case 'sha384':
                $hashLength = 64;
                break;
            case 'sha512':
                $hashLength = 88;
                break;
            default:
                $hashLength = 44;
                break;
        }
        if (strlen($hash) !== $hashLength) {
            throw InvalidArgumentException::badHash();
        }
        $policy = '\'' . $algo . '-' . $hash . '\'';
        if (count($this->styleSrc) > 0) {
            if ($this->styleSrc[0] === '\'none\'') {
                $this->styleSrc[0] = $policy;
                return true;
            }
        }
        $this->styleSrc[] = $policy;
        return true;
    }//end addScriptHash()

    /**
     * Adds a nonce to script or style policy.
     *
     * @param string $directive The directive to add the nonce to.
     * @param string $nonce     The base64 nonce to use.
     *
     * @return bool True on success, False on failure
     */
    public function addNonce(string $directive, string $nonce): bool
    {
        $nonce = trim($nonce);
        if (! $this->validateNonce($nonce)) {
            throw InvalidArgumentException::badNonce($nonce);
        }
        $directive = trim(strtolower($directive));
        if (! in_array($directive, array('default-src', 'script-src', 'style-src'))) {
            return false;
        }
        $policy = '\'nonce-' . $nonce . '\'';
        switch ($directive) {
            case 'default-src':
                if (in_array($policy, $this->defaultSrc)) {
                    return true;
                }
                $n = array_search('\'unsafe-inline\'', $this->defaultSrc);
                if ($n === false) {
                    if ($this->checkForNone($this->defaultSrc)) {
                        $this->defaultSrc = array($policy);
                    } else {
                        $this->defaultSrc[] = $policy;
                    }
                } else {
                    $this->defaultSrc[$n] = $policy;
                }
                break;
            case 'script-src':
                if (in_array($policy, $this->scriptSrc)) {
                    return true;
                }
                $n = array_search('\'unsafe-inline\'', $this->scriptSrc);
                if ($n === false) {
                    if ($this->checkForNone($this->scriptSrc)) {
                        $this->scriptSrc = array($policy);
                    } else {
                        $this->scriptSrc[] = $policy;
                    }
                } else {
                    $this->scriptSrc[$n] = $policy;
                }
                break;
            default:
                if (in_array($policy, $this->styleSrc)) {
                    return true;
                }
                $n = array_search('\'unsafe-inline\'', $this->styleSrc);
                if ($n === false) {
                    if ($this->checkForNone($this->styleSrc)) {
                        $this->styleSrc = array($policy);
                    } else {
                        $this->styleSrc[] = $policy;
                    }
                } else {
                    $this->styleSrc[$n] = $policy;
                }
                break;
        }
        return true;
    }//end addNonce()

    /**
     * Set the 'strict-dynamic' parameter to the script-src or default-src directive.
     *
     * @param string $directive The CSP directive to add the parameter to.
     *
     * @return bool True on success, False on failure.
     */
    protected function setStrictDynamic(string $directive): bool
    {
        if (! in_array($directive, array('default-src', 'script-src'))) {
            return false;
        }
        $nonceHash = false;
        switch ($directive) {
            case 'default-src':
                foreach ($this->defaultSrc as $param) {
                    if (substr($param, 0, 7) === '\'nonce-') {
                        $nonceHash = true;
                    }
                }
                if ($nonceHash) {
                    if (! in_array('\'strict-dynamic\'', $this->defaultSrc)) {
                        $this->defaultSrc[] = '\'strict-dynamic\'';
                    }
                    return true;
                }
                break;
            case 'script-src':
                foreach ($this->scriptSrc as $param) {
                    if (substr($param, 0, 7) === '\'nonce-') {
                        $nonceHash = true;
                    }
                }
                foreach ($this->scriptSrc as $param) {
                    if (substr($param, 0, 8) === '\'sha256-') {
                        $nonceHash = true;
                    }
                }
                foreach ($this->scriptSrc as $param) {
                    if (substr($param, 0, 8) === '\'sha384-') {
                        $nonceHash = true;
                    }
                }
                foreach ($this->scriptSrc as $param) {
                    if (substr($param, 0, 8) === '\'sha512-') {
                        $nonceHash = true;
                    }
                }
                if ($nonceHash) {
                    if (! in_array('\'strict-dynamic\'', $this->scriptSrc)) {
                        $this->scriptSrc[] = '\'strict-dynamic\'';
                    }
                    return true;
                }
                break;
            default:
                return false;
                break;
        }
        return false;
    }//end setStrictDynamic()

    /**
     * Add a host to a directive policy
     *
     * @param string $directive The CSP policy directive.
     * @param string $url       The host-source policy to set.
     *
     * @return bool
     */
    protected function addHostPolicy(string $directive, string $url)
    {
        if ($url === '*') {
            trigger_error('Setting a host policy parameter to \'*\' is allowed but is not secure.', E_USER_NOTICE);
            return $this->setPolicyParameter($directive, '*');
        }
        $wildport = false;
        if (substr($url, -2) === ':*') {
            $wildport = true;
            $url = preg_replace('/\:\*/', '', $url);
        }
        if (substr_count($url, ':') === 0) {
            $parse = array();
            $testurl = $url;
            if (function_exists('idn_to_ascii')) {
                $testurl = strtolower(idn_to_ascii($url));
            } else {
                $testurl = strtolower($url);
            }
            $ttesturl = preg_replace('/^\*\./', '', $testurl);
            if (filter_var('http://' . $ttesturl, FILTER_VALIDATE_URL) === false) {
                throw InvalidArgumentException::invalidHostName();
            } else {
                $parse['host'] = $testurl;
            }
        } else {
            $parse = parse_url($url);
        }
        if (isset($parse['user'])) {
            throw InvalidArgumentException::invalidHostSource();
        }
        if (isset($parse['pass'])) {
            throw InvalidArgumentException::invalidHostSource();
        }
        if (isset($parse['path'])) {
            throw InvalidArgumentException::invalidHostSource();
        }
        if (isset($parse['query'])) {
            throw InvalidArgumentException::invalidHostSource();
        }
        if (isset($parse['fragment'])) {
            throw InvalidArgumentException::invalidHostSource();
        }
        if (! isset($parse['host'])) {
            throw InvalidArgumentException::invalidHostSource();
        }
        if (function_exists('idn_to_ascii')) {
            $parse['host'] = strtolower(idn_to_ascii($parse['host']));
        } else {
            $parse['host'] = strtolower($parse['host']);
        }
        $policy = '';
        if (isset($parse['scheme'])) {
            $scheme = strtolower($parse['scheme']);
            if (! in_array($scheme, array('http', 'https'))) {
                throw InvalidArgumentException::invalidHostScheme();
            }
            if ($scheme === 'http') {
                trigger_error('Use of \'http\' in a host source is allowed but is not secure.', E_USER_NOTICE);
            }
            $policy = $scheme . '://';
        } else {
            trigger_error('Not specifying a URL scheme in a host source is allowed but is not secure.', E_USER_NOTICE);
        }
        $policy .= $parse['host'];
        if (isset($parse['port'])) {
            $policy = $policy . ':' . $parse['port'];
        }
        if ($wildport) {
            $policy .= ':*';
        }
        return $this->setPolicyParameter($directive, $policy);
    }//end addHostPolicy()

    /**
     * Add or create a policy to a fetch directive.
     *
     * @param string $directive The CSP policy directive.
     * @param string $policy    The CSP policy parameter.
     *
     * @return bool True on success, False on failure.
     */
    public function addFetchPolicy(string $directive, string $policy): bool
    {
        $directive = trim(strtolower($directive));
        $policy = $this->adjustPolicy($policy);
        if ($directive === 'default-src') {
            throw InvalidArgumentException::invalidDefaultSrc();
        }
        if ($directive === 'child-src') {
            throw InvalidArgumentException::invalidChildSrc();
        }
        if (! in_array($directive, $this->fetchDirectives)) {
            throw InvalidArgumentException::invalidFetchDirective($directive);
        }
        $policyType = null;
        if (in_array($policy, array('\'none\'', '\'self\''))) {
            $policyType = 'keyword';
        }
        if (is_null($policyType)) {
            if (in_array($policy, array('\'unsafe-inline\'', '\'unsafe-eval\''))) {
                $policyType = 'unsafe';
            }
        }
        if (is_null($policyType)) {
            if (substr($policy, -1) === ':') {
                $policyType = 'scheme';
            }
        }
        if (is_null($policyType)) {
            $test = strtolower(substr($policy, 0, 7));
            if (substr($test, 0, 3) === 'sha') {
                $htype = substr($test, 3, 4);
                switch ($htype) {
                    case '256-':
                        $policyType = 'hash';
                        break;
                    case '384-':
                        $policyType = 'hash';
                        break;
                    case '512-':
                        $policyType = 'hash';
                        break;
                }
            }
        }
        if (is_null($policyType)) {
            $test = strtolower(substr($policy, 0, 6));
            if ($test === 'nonce-') {
                $policyType = 'nonce';
            }
        }
        switch ($policyType) {
            case 'keyword':
                return $this->addPolicyKeyword($directive, $policy);
                break;
            case 'scheme':
                $policy = strtolower($policy);
                if (! in_array($policy, array('https:', 'data:', 'mediastream:', 'blob:', 'filesystem:'))) {
                    throw InvalidArgumentException::invalidFetchScheme($policy);
                }
                if (in_array($policy, array('data:', 'mediastream:', 'blob:', 'filesystem:'))) {
                    $warning = "Use of the 'data:', 'mediastream:', 'blob:', and 'filesystem:' scheme sources in CSP";
                    $warning .=" are allowed but strongly cautioned against.";
                    trigger_error($warning, E_USER_NOTICE);
                }
                return $this->setPolicyParameter($directive, $policy);
                break;
            case 'unsafe':
                return $this->addUnsafe($directive, $policy);
                break;
            case 'hash':
                $arr = explode('-', $policy);
                $algo = $arr[0];
                $hash = $arr[1];
                if ($directive === 'script-src') {
                    return $this->addScriptHash($algo, $hash);
                }
                if ($directive === 'style-src') {
                    return $this->addStyleHash($algo, $hash);
                }
                break;
            case 'nonce':
                $arr = explode('-', $policy);
                $nonce = $arr[1];
                return $this->addNonce($directive, $nonce);
              break;
            default:
                if ($directive === 'script-src') {
                    if ($policy === '\'strict-dynamic\'') {
                        return $this->setStrictDynamic('script-src');
                    }
                    if ($policy === '\'report-sample\'') {
                        if (! is_null($this->reportUri)) {
                            return $this->setPolicyParameter('script-src', $policy);
                        } else {
                            return false;
                        }
                    }
                }
                // default to url
                return $this->addHostPolicy($directive, $policy);
        }
        return false;
    }//end addFetchPolicy()

    /**
     * This generates a nonce. A nonce for CSP is a different concept than with cryptography.
     *
     * In cryptography, a nonce only needs to be unique, it is okay if it is relatively
     * predictable, it just can't be reused with the same secret. With CSP, it can not be
     * predictable so it is not something that can just be incremented after each use.
     *
     * If a nonce less than 16 bytes is requested, it rejects it and generated 16 bytes
     * per https://w3c.github.io/webappsec-csp/#security-considerations
     *
     * This function also can produce a suitable CSRF token.
     *
     * @param int $bytes How many bytes should be used. Defaults to 8.
     *
     * @return string A base64 encoded random nonce.
     */
    public static function generateNonce(int $bytes = 16): string
    {
        if ($bytes < 16) {
            $bytes = 16;
        }
        $random = random_bytes($bytes);
        return base64_encode($random);
    }//end generateNonce()

    /**
     * Copies the content of the default-src directive into the specified directive.
     *
     * @param string $directive The directive to copy default-src into.
     *
     * @return bool True on success, False on failure.
     */
    public function copyDefaultFetchPolicy(string $directive): bool
    {
        $directive = trim(strtolower($directive));
        switch ($directive) {
            case 'connect-src':
                $this->connectSrc = $this->defaultSrc;
                break;
            case 'font-src':
                $this->fontSrc = $this->defaultSrc;
                break;
            case 'frame-src':
                $this->frameSrc = $this->defaultSrc;
                break;
            case 'img-src':
                $this->imgSrc = $this->defaultSrc;
                break;
            case 'manifest-src':
                $this->manifestSrc = $this->defaultSrc;
                break;
            case 'media-src':
                $this->mediaSrc = $this->defaultSrc;
                break;
            case 'object-src':
                $this->objectSrc = $this->defaultSrc;
                break;
            case 'script-src':
                $this->scriptSrc = $this->defaultSrc;
                break;
            case 'style-src':
                $this->styleSrc = $this->defaultSrc;
                break;
            case 'worker-src':
                $this->workerSrc = $this->defaultSrc;
                break;
            default:
                return false;
                break;
        }
        return true;
    }//end copyDefaultFetchPolicy()

    /**
     * Creates the CSP header string.
     *
     * @param bool $generateChildSrc Whether or not to create the child-src directive if needed.
     *
     * @return string
     */
    public function buildHeader(bool $generateChildSrc = true): string
    {
        $directives = array();
        $directives[] = 'default-src ' . implode(' ', $this->defaultSrc) . ';';

        /* These inherit from default if empty */

        /* child-src is deprecated but some browsers may still need it */
        if ($generateChildSrc) {
            $childSrc = $this->generateChildFetchDirective();
        } else {
            $childSrc = array();
        }
        if ($childSrc === $this->defaultSrc) {
            $childSrc = array();
        } else {
            if (count($childSrc) > 0) {
                // check for empty frameSrc
                if (count($this->frameSrc) === 0) {
                    $this->copyDefaultFetchPolicy('frame-src');
                }
                // check for empty workerSrc
                if (count($this->workerSrc) === 0) {
                    $this->copyDefaultFetchPolicy('worker-src');
                }
                $directives[] = 'child-src ' . implode(' ', $childSrc) . ';';
            }
        }

        if ($this->connectSrc !== $this->defaultSrc) {
            if (count($this->connectSrc) > 0) {
                $directives[] = 'connect-src ' . implode(' ', $this->connectSrc) . ';';
            }
        }
        if ($this->fontSrc !== $this->defaultSrc) {
            if (count($this->fontSrc) > 0) {
                $directives[] = 'font-src ' . implode(' ', $this->fontSrc) . ';';
            }
        }

        // special case due to deprecated childSrc
        $directiveAdded = false;
        if (count($childSrc) > 0) {
            if (count($this->frameSrc) === 0) {
                //explicitly set to default
                $directives[] = 'frame-src ' . implode(' ', $this->defaultSrc) . ';';
                $directiveAdded = true;
            } elseif ($this->frameSrc === $this->defaultSrc) {
                //explicitly set to default
                $directives[] = 'frame-src ' . implode(' ', $this->defaultSrc) . ';';
                $directiveAdded = true;
            }
        }
        if (! $directiveAdded) {
            if ($this->frameSrc !== $this->defaultSrc) {
                if (count($this->frameSrc) > 0) {
                    $directives[] = 'frame-src ' . implode(' ', $this->frameSrc) . ';';
                }
            }
        }
        // end special case

        if ($this->imgSrc !== $this->defaultSrc) {
            if (count($this->imgSrc) > 0) {
                $directives[] = 'img-src ' . implode(' ', $this->imgSrc) . ';';
            }
        }
        if ($this->manifestSrc !== $this->defaultSrc) {
            if (count($this->manifestSrc) > 0) {
                $directives[] = 'manifest-src ' . implode(' ', $this->manifestSrc) . ';';
            }
        }
        if ($this->mediaSrc !== $this->defaultSrc) {
            if (count($this->mediaSrc) > 0) {
                $directives[] = 'media-src ' . implode(' ', $this->mediaSrc) . ';';
            }
        }
        if ($this->objectSrc !== $this->defaultSrc) {
            if (count($this->objectSrc) > 0) {
                $directives[] = 'object-src ' . implode(' ', $this->objectSrc) . ';';
            }
        }
        if ($this->scriptSrc !== $this->defaultSrc) {
            if (count($this->scriptSrc) > 0) {
                $directives[] = 'script-src ' . implode(' ', $this->scriptSrc) . ';';
            }
        }
        if ($this->styleSrc !== $this->defaultSrc) {
            if (count($this->styleSrc) > 0) {
                $directives[] = 'style-src ' . implode(' ', $this->styleSrc) . ';';
            }
        }

        // special case due to deprecated childSrc
        $directiveAdded = false;
        if (count($childSrc) > 0) {
            if (count($this->workerSrc) === 0) {
                //explicitly set to default
                $directives[] = 'worker-src ' . implode(' ', $this->defaultSrc) . ';';
                $directiveAdded = true;
            } elseif ($this->workerSrc === $this->defaultSrc) {
                //explicitly set to default
                $directives[] = 'worker-src ' . implode(' ', $this->defaultSrc) . ';';
                $directiveAdded = true;
            }
        }
        if (! $directiveAdded) {
            if ($this->workerSrc !== $this->defaultSrc) {
                if (count($this->workerSrc) > 0) {
                    $directives[] = 'worker-src ' . implode(' ', $this->workerSrc) . ';';
                }
            }
        }
        // end special case

        /* These do not inherit from default if empty */

        // missing baseURI

        if (count($this->pluginTypes) > 0) {
            if ($this->objectsAllowed()) {
                $directives[] = 'plugin-types ' . implode(' ', $this->pluginTypes) . ';';
            }
        }
        if (count($this->sandbox) > 0) {
            $directives[] = 'sandbox ' . implode(' ', $this->sandbox) . ';';
        }
        if (count($this->formAction) > 0) {
            $directives[] = 'form-action ' . implode(' ', $this->formAction) . ';';
        }
        if (count($this->frameAncestors) > 0) {
            $directives[] = 'frame-ancestors ' . implode(' ', $this->frameAncestors) . ';';
        }
        
        if (! is_null($this->reportUri)) {
            $directives[] = 'report-uri' . ' ' . $this->reportUri . ';';
        }
        return implode(' ', $directives);
    }//end buildHeader()

    /**
     * Sends the content security policy header.
     *
     * @param bool $generateChildSrc Whether or not to create the child-src directive if needed.
     *
     * @return void
     */
    public function sendCspHeader(bool $generateChildSrc = true): void
    {
        $string = $this->buildHeader($generateChildSrc);
        $headerName = 'Content-Security-Policy';
        if (! is_null($this->reportUri)) {
            if ($this->reportOnly) {
                $headerName .= '-Report-Only';
            }
        }
        header($headerName . ': ' . $string);
        return;
    }//end sendCspHeader()

    /**
     * The constructor function
     *
     * @param null|string $param      The optional path to a JSON configuration file or a default
     *                                policy for default-src.
     * @param bool        $reportOnly Only report violations if True, block violations if False.
     *                                Defaults to False.
     */
    public function __construct($param = null, bool $reportOnly = false)
    {
        if ($reportOnly) {
            $this->reportOnly = true;
        }
        if (is_null($param)) {
            $this->setPolicyParameter('script-src', '\'self\'');
            $this->setPolicyParameter('connect-src', '\'self\'');
            $this->setPolicyParameter('style-src', '\'self\'');
            $this->setPolicyParameter('img-src', '\'self\'');
            $this->setPolicyParameter('media-src', '\'self\'');
        } else {
            $param = trim($param);
            $param = preg_replace('/\s+/', ' ', $param);
            $arr = explode(' ', $param);
            foreach ($arr as $policy) {
                $policy = $this->adjustPolicy($policy);
                if (in_array($policy, array(
                    '\'none\'',
                    '\'self\'',
                    '\'unsafe-inline\'',
                    '\'unsafe-eval\'',
                    'https:',
                    'data:',
                    'mediastream:',
                    'blob:',
                    'filesystem:'
                ))) {
                    if (in_array($policy, array(
                            'data:',
                            'mediastream:',
                            'blob:',
                            'filesystem:'
                        ))) {
                        $warning = "Use of the 'data:', 'mediastream:', 'blob:', ";
                        $warning .= "and 'filesystem:' scheme sources in CSP";
                        $warning .=" are allowed but strongly cautioned against.";
                        trigger_error($warning, E_USER_NOTICE);
                    }
                    $this->setPolicyParameter('default-src', $policy);
                } else {
                    $test = strtolower(substr($policy, 0, 6));
                    if ($test === 'nonce-') {
                        $narr = explode('-', $policy);
                        $nonce = $narr[1];
                        $this->addNonce('default-src', $nonce);
                    } elseif ($policy === '\'strict-dynamic\'') {
                        $this->setStrictDynamic('default-src');
                    } else {
                        $this->addHostPolicy('default-src', $policy);
                    }
                }
            }
        }
    }//end __construct()
}//end class

?>