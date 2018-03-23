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

namespace AWonderPHP\SimpleCacheAPCu;

/**
 * An implementation of the PSR-16 SimpleCache Interface for APCu.
 *
 * This class implements the [PHP-FIG PSR-16](https://www.php-fig.org/psr/psr-16/)
 *  interface for a cache class.
 *
 * It needs PHP 7.1 or newer and obviously the [APCu PECL](https://pecl.php.net/package/APCu) extension.
 *  I am not sure of the minimum APCu version, I am using 5.1.9 myself at the moment.
 */
class ContentSecurityPolicy
{
    /* CSP Level 1 less deprecated frame-src */
    
    /**
     * Default policy for loading content such as JavaScript, Images, CSS, Fonts, AJAX
     * requests, Frames, HTML5 Media.
     *
     * @var array
     */
    protected $defaultSrc = array('\'self\'');
    
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
    protected $connectSrc = array('\'self\'');
    
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
    protected $objectSrc = array('\'self\'');
    
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
     * @var null|array
     */
    protected $sandbox = null;
    
    /**
     * Allowed sandbox values
     *
     * @var array
     */
    protected $legalSandboxValues = array(
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
    protected $childSrc = array('\'self\'');
    
    /**
     * Defines valid sources that can be used as a HTML <form> action.
     *
     * @var array
     */
    protected $formAction = array('\'self\'');
    
    /**
     * Defines valid sources for embedding the resource using <frame> <iframe> <object>
     * <embed> <applet>. Setting this directive to 'none' should be roughly equivalent to
     * X-Frame-Options: DENY
     *
     * @var array
     */
    protected $frameAncestors = array('\'none\'');
    
    /**
     * Defines valid MIME types for plugins invoked via <object> and <embed>. To load an
     * <applet> you must specify application/x-java-applet.
     *
     * @var array
     */
    protected $pluginTypes = array('image/svg+xml', 'application/pdf');
    
    /**
     * Non URL Source List Keywords
     *
     * @var array
     *
     */
    protected $sourceKeywords = array(
        '*',
        '\'none\'',
        '\'self\'',
        'data:',
        'https:',
        '\'unsafe-inline\'',
        '\'unsafe-eval\''
    );
    
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
        $directive = trim(strtolower($directive));
        $keyword = trim(strtolower($keyword));
        if (! in_array($keyword, array('*', '\'none\'', 'https:'))) {
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
        $directive = trim(strtolower($directive));
        $unsafe = trim(strtolower($unsafe));
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
     * Adds a nonce to script or style policy.
     *
     * @param string $directive The directive to add the nonce to.
     * @param string $nonce     The hex or base64 nonce to use.
     *
     * @return bool True on success, False on failure
     */
    public function addNonce($directive, $nonce)
    {
        $nonce = trim($nonce);
        if (! ctype_xdigit($nonce)) {
            if (base64_encode(base64_decode($nonce)) !== $nonce) {
              #fixme throw exception
                return false;
            }
        }
        $directive = trim(strtolower($directive));
        if (! in_array($directive, array('script-src', 'style-src'))) {
            return false;
        }
        $policy = '\'nonce-' . $nonce . '\'';
        switch ($directive) {
            case 'script-src':
                $this->scriptSrc[] = $policy;
                break;
            default:
                $this->styleSrc[] = $policy;
        }
        return true;
    }//end addNonce()

    /**
     * This generates a nonce. A nonce for CSP is a different concept than with cryptography.
     *
     * In crytography, a nonce only needs to be unique, it is okay if it is relatively
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
    public function generateNonce(int $bytes = 8): string
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
        if ($this->styleSrc !== $this->defaultSrc) {
            if (count($this->styleSrc) > 0) {
                $directives[] = 'style-src ' . implode(' ', $this->styleSrc) . ';';
            }
        }
        if ($this->imgSrc !== $this->defaultSrc) {
            if (count($this->imgSrc) > 0) {
                $directives[] = 'img-src ' . implode(' ', $this->imgSrc) . ';';
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
        if (! is_null($this->sandbox)) {
            $directives[] = 'sandbox ' . implode(' ', $this->sandbox) . ';';
        }
        if ($this->formAction !== $this->defaultSrc) {
            if (count($this->formAction) > 0) {
                $directives[] = 'formaction ' . implode(' ', $this->formAction) . ';';
            }
        }
        if (count($this->frameAncestors) > 0) {
            $directives[] = 'frame-ancestors ' . implode(' ', $this->frameAncestors) . ';';
        }
        if (count($this->pluginTypes) > 0) {
            $directives[] = 'plugin-types ' . implode(' ', $this->pluginTypes) . ';';
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
}//end class

?>