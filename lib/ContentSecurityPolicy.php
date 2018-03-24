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
 * Based on the specification at https://content-security-policy.com/ but is bit more restrictive
 * with the nonce, where it requires the nonce be base64 encoded or hex encoded string.
 *
 */
class ContentSecurityPolicy
{
    /**
     * Valid CSP Level 1/2 Directives except for default-src
     *
     * @var array
     */
    protected $validDirectives = array(
        'script-src',
        'style-src',
        'img-src',
        'connect-src',
        'font-src',
        'object-src',
        'media-src',
        'child-src',
        'sandbox',
        'form-action',
        'frame-ancestors',
        'plugin-types',
        'report-uri'
    );
    
    /* CSP Level 1 less deprecated frame-src */
    
    /**
     * Default policy for loading content such as JavaScript, Images, CSS, Fonts, AJAX
     * requests, Frames, HTML5 Media.
     *
     * @var array
     */
    protected $defaultSrc = array('\'none\'');
    
    /**
     * Defines valid sources of JavaScript. Uses defaultSrc when null
     *
     * @var array
     */
    protected $scriptSrc = array();
    
    /**
     * Defines valid sources of stylesheets.
     *
     * @var array
     */
    protected $styleSrc = array();
    
    /**
     * Defines valid sources of images.
     *
     * @var array
     */
    protected $imgSrc = array();
    
    /**
     * Applies to XMLHttpRequest (AJAX), WebSocket or EventSource. If not allowed the browser
     * emulates a 400 HTTP status code.
     *
     * @var array
     */
    protected $connectSrc = array();
    
    /**
     * Defines valid sources of fonts.
     *
     * @var array
     */
    protected $fontSrc = array();
    
    /**
     * Defines valid sources of plugins, eg <object>, <embed> or <applet>.
     *
     * @var array
     */
    protected $objectSrc = array();
    
    /**
     * Defines valid sources of audio and video, eg HTML5 <audio>, <video> elements.
     *
     * @var array
     */
    protected $mediaSrc = array();
    
    /**
     * Enables a sandbox for the requested resource similar to the iframe sandbox attribute.
     * The sandbox applies a same origin policy, prevents popups, plugins and script execution
     * is blocked. You can keep the sandbox value empty to keep all restrictions in place, or
     * add values.
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
        'allow-same-origin',
        'allow-scripts',
        'allow-popups',
        'allow-modals',
        'allow-orientation-lock',
        'allow-pointer-lock',
        'allow-presentation',
        'allow-popups-to-escape-sandbox',
        'allow-top-navigation'
        );
    
    /**
     * Instructs the browser to POST reports of policy failures to this URI.
     *
     * @var null|string
     */
    protected $reportUri = null;
    
    /**
     * Changes report-uri header to report-uri-Report-Only so that the resource violation is
     * reported but is not actually blocked.
     *
     * @var bool
     */
    protected $reportOnly = false;
    
    /* CSP Level 2 additions */
    
    /**
     * Defines valid sources for web workers and nested browsing contexts loaded using
     * elements such as <frame> and <iframe>
     *
     * @var array
     */
    protected $childSrc = array();
    
    /**
     * Defines valid sources that can be used as a HTML <form> action.
     *
     * @var array
     */
    protected $formAction = array();
    
    /**
     * Defines valid sources for embedding the resource using <frame> <iframe> <object>
     * <embed> <applet>. Setting this directive to 'none' should be roughly equivalent to
     * X-Frame-Options: DENY
     *
     * @var array
     */
    protected $frameAncestors = array();
    
    /**
     * Defines valid MIME types for plugins invoked via <object> and <embed>. To load an
     * <applet> you must specify application/x-java-applet.
     *
     * @var array
     */
    protected $pluginTypes = array('image/svg+xml', 'application/pdf');
    
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
        }
        return $policy;
    }//end adjustPolicy()

    
    /**
     * Defines the policy to the specified policy keyword. This is for
     * keywords where the keyword implies only policy for directive.
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
            case 'script-src':
                $this->scriptSrc = array($keyword);
                break;
            case 'style-src':
                $this->styleSrc = array($keyword);
                break;
            case 'img-src':
                $this->imgSrc = array($keyword);
                break;
            case 'connect-src':
                $this->connectSrc = array($keyword);
                break;
            case 'font-src':
                $this->fontSrc = array($keyword);
                break;
            case 'object-src':
                $this->objectSrc = array($keyword);
                break;
            case 'media-src':
                $this->mediaSrc = array($keyword);
                break;
            case 'child-src':
                $this->childSrc = array($keyword);
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
        if (! in_array($unsafe, array('unsafe-inline', 'unsafe-eval'))) {
            return false;
        }
        switch ($unsafe) {
            case 'unsafe-inline':
                if ($directive === 'script-src') {
                    $this->scriptSrc[] = 'unsafe-inline';
                    return true;
                }
                if ($directive === 'style-src') {
                    $this->styleSrc[] = 'unsafe-inline';
                    return true;
                }
                break;
            default:
                if ($directive === 'script-src') {
                    $this->scriptSrc[] = 'unsafe-eval';
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
     * Adds a nonce to script or style policy.
     *
     * @param string $directive The directive to add the nonce to.
     * @param string $nonce     The hex or base64 nonce to use.
     *
     * @return bool True on success, False on failure
     */
    public function addNonce($directive, string $nonce)
    {
        // FIXME - make sure it makes sense to add
        $nonce = trim($nonce);
        if (! ctype_xdigit($nonce)) {
            if (base64_encode(base64_decode($nonce)) !== $nonce) {
                throw InvalidArgumentException::badNonce($nonce);
            }
        }
        $directive = trim(strtolower($directive));
        if (! in_array($directive, array('script-src', 'style-src'))) {
            return false;
        }
        $policy = '\'nonce-' . $nonce . '\'';
        switch ($directive) {
            case 'script-src':
                if (! $this->checkInlineScriptsAllowed()) {
                    return false;
                }
                $this->scriptSrc[] = $policy;
                break;
            default:
                if (! $this->checkInlineStyleAllowed()) {
                    return false;
                }
                $this->styleSrc[] = $policy;
        }
        return true;
    }//end addNonce()
    
    /**
     * Adds script sha256. Throws exception if invalid.
     *
     * @param string $hash The sha256 sum to allow.
     *
     * @return bool
     */
    public function addInlineScriptHash($hash): bool
    {
        if (! $this->checkInlineScriptsAllowed()) {
            return false;
        }
        if (ctype_xdigit($hash)) {
            $raw = hex2bin($hash);
            $hash = base64_encode($hash);
        }
        if (base64_encode(base64_decode($hash)) !== $hash) {
            throw InvalidArgumentException::badHash();
        }
        if (strlen($hash) !== 44) {
            throw InvalidArgumentException::badHash();
        }
        $policy = '\'sha256-' . $hash . '\'';
        $this->scriptSrc[] = $policy;
        return true;
    }//end addInlineScriptHash()


    /**
     * This generates a nonce. A nonce for CSP is a different concept than with cryptography.
     *
     * In cryptography, a nonce only needs to be unique, it is okay if it is relatively
     * predictable, it just can't be reused with the same secret. With CSP, it can not be
     * predictable so it is not something that can just be incremented after each use.
     *
     * If a nonce less than 8 bytes is requested, it rejects it and generated 8 bytes.
     *
     * This function also can produce a suitable CSRF token.
     *
     * @param int $bytes How many bytes should be used. Defaults to 8.
     *
     * @return string A base64 encoded random nonce
     */
    public static function generateNonce(int $bytes = 8): string
    {
        if ($bytes < 8) {
            $bytes = 8;
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
        if ($this->scriptSrc !== $this->defaultSrc) {
            if (count($this->scriptSrc) > 0) {
                $directives[] = 'script-src ' . implode(' ', $this->scriptSrc) . ';';
            }
        }
        if ($this->connectSrc !== $this->defaultSrc) {
            if (count($this->connectSrc) > 0) {
                $directives[] = 'connect-src ' . implode(' ', $this->connectSrc) . ';';
            }
        }
        if ($this->imgSrc !== $this->defaultSrc) {
            if (count($this->imgSrc) > 0) {
                $directives[] = 'img-src ' . implode(' ', $this->imgSrc) . ';';
            }
        }
        if ($this->styleSrc !== $this->defaultSrc) {
            if (count($this->styleSrc) > 0) {
                $directives[] = 'style-src ' . implode(' ', $this->styleSrc) . ';';
            }
        }
        if ($this->fontSrc !== $this->defaultSrc) {
            if (count($this->fontSrc) > 0) {
                $directives[] = 'font-src ' . implode(' ', $this->fontSrc) . ';';
            }
        }
        if ($this->objectSrc !== $this->defaultSrc) {
            if (count($this->objectSrc) > 0) {
                $directives[] = 'object-src ' . implode(' ', $this->objectSrc) . ';';
            }
        }
        if ($this->mediaSrc !== $this->defaultSrc) {
            if (count($this->mediaSrc) > 0) {
                $directives[] = 'media-src ' . implode(' ', $this->mediaSrc) . ';';
            }
        }
        if ($this->childSrc !== $this->defaultSrc) {
            if (count($this->childSrc) > 0) {
                $directives[] = 'child-src ' . implode(' ', $this->childSrc) . ';';
            }
        }
        if (count($this->sandbox) > 0) {
            $directives[] = 'sandbox ' . implode(' ', $this->sandbox) . ';';
        }
        if ($this->formAction !== $this->defaultSrc) {
            if (count($this->formAction) > 0) {
                $directives[] = 'form-action ' . implode(' ', $this->formAction) . ';';
            }
        }
        if (count($this->frameAncestors) > 0) {
            $directives[] = 'frame-ancestors ' . implode(' ', $this->frameAncestors) . ';';
        }
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