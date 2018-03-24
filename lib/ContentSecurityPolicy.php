<?php
declare(strict_types=1);

/**
 * An implementation of Content Security Policy
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
     * Valid CSP Directives except for default-src.
     *
     * @var array
     */
    protected $validDirectives = array(
        'connect-src',
        'font-src',
        'frame-src',
        'img-src',
        'manifest-src',
        'media-src',
        'object-src',
        'script-src',
        'style-src',
        'worker-src',
        'base-uri',
        'plugin-types',
        'sandbox',
        'form-action',
        'frame-ancestors',
        'report-uri'
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
     * Adjust the policy to add single upquote where needed
     *
     * @param string $policy The policy string to adjust.
     *
     * @return string
     */
    protected function adjustPolicy($policy)
    {
        $policy = trim($policy);
        $test = strtolower($policy);
        switch ($test) {
            case 'none':
                $policy = ('\'none\'');
                break;
            case '\'none\'':
                $policy = ('\'none\'');
                break;
            case 'self':
                $policy = ('\'self\'');
                break;
            case '\'self\'':
                $policy = ('\'self\'');
                break;
            case 'unsafe-inline':
                $policy = ('\'unsafe-inline\'');
                break;
            case '\'unsafe-inline\'':
                $policy = ('\'unsafe-inline\'');
                break;
            case 'unsafe-eval':
                $policy = ('\'unsafe-eval\'');
                break;
            case '\'unsafe-eval\'':
                $policy = ('\'unsafe-eval\'');
                break;
        }
        return $policy;
    }//end adjustPolicy()

    
    /**
     * Defines the policy to the specified policy keyword. This is for
     * keywords where the keyword implies first or only policy for directive.
     *
     * @param string $directive  The directive to be defined.
     * @param string $keyword    The policy keyword.
     *
     * @return bool
     */
    protected function definePolicy($directive, $keyword): bool
    {
        if (! in_array($keyword, array('*', '\'self\'', '\'none\'', 'https:'))) {
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
    }//end definePolicy()

    
    /**
     * Adds unsafe-inline or unsafe-eval to script/style directive.
     *
     * @param string $directive The directive to be defined.
     * @param string $unsafe    The unsafe policy.
     *
     * @return bool True on success, False on failure.
     */
    protected function addUnsafe($directive, $unsafe): bool
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
            default:
                if ($directive === 'script-src') {
                    $this->scriptSrc[] = '\'unsafe-eval\'';
                    return true;
                }
        }
        return false;
    }//end addUnsafe()
    
    /**
     * Checks to see whether inline scripts are allowed in current policy
     *
     * @return bool
     */
    protected function checkInlineScriptsAllowed()
    {
        $n = count($this->scriptSrc);
        switch ($n) {
            case 0:
                $defaultPolicy = $this->defaultSrc[0];
                if ($defaultPolicy === '\'none\'') {
                    return false;
                }
                break;
            case 1:
                $scriptPolicy = $this->scriptSrc[0];
                if ($scriptPolicy === '\'none\'') {
                    return false;
                }
                break;
        }
        return true;
    }//end checkInlineScriptsAllowed()

    
    /**
     * Checks to see whether inline style are allowed in current policy
     *
     * @return bool
     */
    protected function checkInlineStyleAllowed()
    {
        $n = count($this->styleSrc);
        switch ($n) {
            case 0:
                $defaultPolicy = $this->defaultSrc[0];
                if ($defaultPolicy === '\'none\'') {
                    return false;
                }
                break;
            case 1:
                $scriptPolicy = $this->styleSrc[0];
                if ($scriptPolicy === '\'none\'') {
                    return false;
                }
                break;
        }
        return true;
    }//end checkInlineStyleAllowed()

    
    /**
     * Add or create a policy to the specified directive
     *
     * @param string $directive The CSP directive to apply the policy to.
     * @param string $policy    The policy to apply to the CSP directive.
     *
     * @return bool True on success, False on failure
     */
    public function addDirectivePolicy(string $directive, string $policy): bool
    {
        $directive = trim(strtolower($directive));
        $policy = $this->adjustPolicy($policy);
        if (! in_array($directive, $this->validDirectives)) {
            throw InvalidArgumentException::invalidDirective($directive);
        }
        switch ($directive) {
            case 'sandbox':
                if (! in_array($policy, $this->validSandboxValues)) {
                    throw InvalidArgumentException::invalidSandboxPolicy($policy);
                }
                if (! in_array($policy, $this->sandbox)) {
                    $this->sandbox[] = $policy;
                }
                return true;
                break;
            default:
                if ($this->definePolicy($directive, $policy)) {
                    return true;
                }
                if ($this->addUnsafe($directive, $policy)) {
                    return true;
                }
                break;
        }
        return false;
    }//end addDirectivePolicy()

    /**
     * Verifies that we have a valid nonce.
     *
     * @param string $nonce the nonce to test.
     *
     * @return bool True when valid, False when invalid
     */
    public function validateNonce(string $nonce): bool
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
     * Adds a nonce to script or style policy.
     *
     * @param string $directive The directive to add the nonce to.
     * @param string $nonce     The base64 nonce to use.
     *
     * @return bool True on success, False on failure
     */
    public function addNonce($directive, string $nonce)
    {
        $nonce = trim($nonce);
        if (! $this->validateNonce($nonce)) {
            throw InvalidArgumentException::badNonce($nonce);
        }
        $directive = trim(strtolower($directive));
        if (! in_array($directive, array('script-src', 'style-src'))) {
            return false;
        }
        $policy = '\'nonce-' . $nonce . '\'';
        switch ($directive) {
            case 'script-src':
                if (in_array($policy, $this->scriptSrc)) {
                    return true;
                }
                $n = array_search('\'unsafe-inline\'', $this->scriptSrc);
                if ($n === false) {
                    $this->scriptSrc[] = $policy;
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
                    $this->styleSrc[] = $policy;
                } else {
                    $this->styleSrc[$n] = $policy;
                }
                break;
        }
        return true;
    }//end addNonce()
    
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
            throw InvalidArgumentException::badAlgo($algo);
        }
        if (! $this->checkInlineScriptsAllowed()) {
            return false;
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
        $this->scriptSrc[] = $policy;
        return true;
    }//end addScriptHash()


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
     * @return string A base64 encoded random nonce
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
     * Creates the CSP header string
     *
     * @return string
     */
    public function buildHeader(): string
    {
        $directives = array();
        $directives[] = 'default-src ' . implode(' ', $this->defaultSrc) . ';';
        
        /* These inherit from default if empty */
        
        /* child-src is deprecated but some browsers may still need it */
        $childSrc = array();
        foreach ($this->frameSrc as $policy) {
            $childSrc[] = $policy;
        }
        foreach ($this->workerSrc as $policy) {
            if (! in_array($policy, $childSrc)) {
                $childSrc[] = $policy;
            }
        }
        if ($childSrc !== $this->defaultSrc) {
            if (count($childSrc) > 0) {
                // check for empty frameSrc
                if (count($this->frameSrc) === 0) {
                    $this->frameSrc[] = '\'none\'';
                }
                // check for empty workerSrc
                if (count($this->workerSrc) === 0) {
                    $this->workerSrc[] = '\'none\'';
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
            $bool = false;
            if (count($this->objectSrc) === 0) {
                if ($this->defaultSrc[0] !== '\'none\'') {
                    $bool = true;
                }
            } else {
                if ($this->objectSrc[0] !== '\'none\'') {
                    $bool = true;
                }
            }
            if ($bool) {
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
            $h = 'report-uri';
            if ($this->reportOnly) {
                $h .= '-ReportOnly';
            }
            $directives[] = $h . ' ' . $this->reportUri . ';';
        }
        return implode(' ', $directives);
    }//end buildHeader()
    
    /**
     * Sends the content security policy header.
     *
     * @return void
     */
    public function sendCspHeader(): void
    {
        $string = $this->buildHeader();
        header('Content-Security-Policy: ' . $string);
        return;
    }//end sendCspHeader()
    
    /**
     * The constructor function
     *
     * @param null|string $param The optional path to a JSON configuration file or a default
     *                           policy for default-src.
     */
    public function __construct($param = null)
    {
        if (is_null($param)) {
            $this->definePolicy('script-src', '\'self\'');
            $this->definePolicy('connect-src', '\'self\'');
            $this->definePolicy('style-src', '\'self\'');
            $this->definePolicy('img-src', '\'self\'');
            $this->definePolicy('media-src', '\'self\'');
        } else {
            $param = trim($param);
            $test = strtolower(substr($param, -5));
            if ($test === '.json') {
              //json file
                $a = 'b';
            } else {
                $arr = explode(';', $param);
                foreach ($arr as $policy) {
                    $policy = $this->adjustPolicy($policy);
                    if (! $this->definePolicy('default-src', $policy)) {
                      //url policy
                        $a = 'b';
                    }
                }
            }
        }
    }//end __construct()
}//end class

?>