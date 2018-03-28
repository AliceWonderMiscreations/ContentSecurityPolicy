ContentSecurityPolicy
=====================

__THIS CLASS IS NOT YET READY FOR USE__

Some stuff here is not fully implemented. Some not at all. Some implemented
stuff not documented.

Content Security Policy (abbreviated as CSP) is a standardized mechanism for
web applications to tell the requesting client what kind of resources are
allowed in a web page and under what conditions they are allowed.

There are three versions of the standard. The third version, known as CSP level
3, is *nearly* finalized but is still in draft form. However even though it is
still in draft form and therefore still subject to change, it is already being
implemented by browsers and is the standard this class is written to implement.


How CSP Works
-------------

Content Security Policy is a collection of directives for different types of
resources a web page might use. These directives are placed together in a
string and served to the client with the web page the policy is to be applied
to.

It can be sent to the client either as a header or as a `<meta>` tag in the
web page. It is preferable to send it as a header. The string containing the
policy will simply be referred to as the “CSP Header” in this document.

If the connection is not served over
[TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) then it is not
that difficult for the attacker to modify or even completely remove the CSP
header, CSP is not an effective means of providing protection to your users if
you do not use TLS.

The CSP header is basically a serialized array of directives, with each
directive specifying a set of policy parameters specific to that directive.

### CSP Directives

Directives are usually classified into five different categories:

1. __Fetch Directives__  
  These directives specify rules regarding where a resource is allowed to come
  from. At least presently, it is easy to distinguish fetch directives from the
  other kind of directives because the directive name *always* ends with `-src`
  and non-fetch directive names *never* end in `-src`. There is a special fetch
  directive called `default-src` that sets the policy for other fetch
  directives when they are not explicitly defined.
2. __Document Directives__  
  These directives specify rules about the properties of a document resource or
  a [Web Worker](https://en.wikipedia.org/wiki/Web_worker) environment.
3. __Navigation Directives__  
  These directives specify rules about locations content can be submitted to or
  locations the user can navigate to.
4. __Reporting Directives__  
  These directives specify if and how policy abuse reporting should be done.
  Presently there are only two reporting directives, one is in the process of
  being deprecated but the other, its replacement, is not currently supported
  by many browsers. Reporting directives *always* begin with `report-`.
5. __Miscellaneous Directives__  
  These are directives that do not fit into the four defined categories. My
  personal opinion is that none of these directives belong as part of CSP but
  presently they are defined by the standard.

The order the directives in the CSP header does not matter, but it is fairly
standard to keep them together and put the fetch directives first, with the
`default-src` directive as the very first directive.


AWonderPHP CSP Class Implementation
===================================

As the rules set within `default-src` apply to any fetch directive that does
not have its own rules specifically defined, I have set `default-src` to the
keyword `'none'` by default in this class. I recommend using the keyword
`'self'` as a starting point for that directive in actual use but it would not
be responsible of me to set that as the default in this class.

For specifics on the individual directives, please see the
[Mozilla MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy).
That is what I am using as the primary guide to the writing of this class, the
W3C documentation is good too but the Mozilla documentation is more concise and
details the actual implementation by a popular browser vendor that has a very
open development process.


With the CSP class here, the CSP header is generated for you using public
class functions that modify the defined directive policies within the class.

The `default-src` directive is treated special. It __MUST__ have a defined
policy and that policy can only be set by the constructor, during class
instantiation.

It is defined as the first argument when calling the class:

    use \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy as CSP;
    $csp = new CSP('self');

You can define more than one parameter in the same string to the constructor,
if you need to:

    $csp = new CSP('self *.cdn.example.com');

Note that I did not put `self` in escaped upquotes. You can if you prefer:

    $csp = new CSP('\'self\' *.cdn.example.com');

or

    $csp = new CSP("'self' *.cdn.example.com");

However, the class does not require it. It identifies when a parameter is a
keyword that needs single quotes around it when the header is sent.

When no argument (or `null`) is fed to the constructor, several relatively safe
defaults kick in.

For fetch directives, the `default-src` directive defaults to `'none'` and
`connect-src`, `img-src`, `media-src`, `script-src`, and `style-src` all will
default to `'self'`.

Please note those defaults *only* take place when the `default-src` directive
is not explicitly set in the constructor. Explicitly setting `default-src` to
`'none'` will __not__ result in those other defaults being set.


Setting Fetch Directive Policy Parameters
-----------------------------------------

With the exception of the `'nonce-[nonce_data]'` policy parameter, parameters
for the `default-src` directive can *only* be defined when the class is
instantiated, as described above. This was a design choice, if you do not like
it there is a button on the github repository you can use to create a fork of
this project where the [MIT License](LICENSE.md) specifically allows you to
make and deploy changes.

Parameters for the `child-src` fetch directive can not *directly* be set with
this class. The `child-src` fetch directive is deprecated, and should only
exist for compatibility with CSP level 2 browsers. This class crafts the policy
for that directives based upon the contents of the `frame-src` and `worker-src`
directives when the CSP header is built.

All other fetch directives can be set with public methods that belong to this
class.

### Basal Keyword Parameters

The `'self'` and `'none'` keywords are treated special by this class. When set,
any previously set parameters for the directive will be replaced.

They can be set with the class `addFetchPolicy($directive, $policy);` method:

    $csp->addFetchPolicy('img-src', 'self');

That will set the state of the `img-src` directive to contain a single parameter
of `'self'`.

    $csp->addFetchPolicy('object-src', 'none');

That will set the state of the `object-src` directive to contain a single
parameter of `'none'`.

Additional parameters can be set after setting those basal keywords. However it
should be noted that sending any parameter after `'none'` will remove the basal
keyword `'none'`.

### Scheme Source Parameters

A scheme source allows you to white-list resources from an entire scheme. I do
not recommend doing this, but it can be useful in migration of a platform to
CSP giving you some CSP protection while you work on adjusting the platform to
work with more specific code.

The allowed scheme source parameters:

* `https:` _Allow the resource to come from any https resource._
* `data:` _Allow `data:` URIs to be used for the resource. This is very insecure._
* `mediastream:` *Allow `mediastream:` URIs to be used for the resource._
* `blob:` _Allow `blob:` URIs to be used for the resource._
* `filesystem:` _Allow `filesystem:` URIs to be used for the content source._

Note that this class does not support the `http:` scheme source even though CSP
itself does. The HTTP protocol is not secure, and content injection attacks are
common. Before using a VPN, I personally experienced them from my ISP
frequently.

Note that all scheme sources *except* for `https:` will throw a warning in your
server log file. If your platform uses them, it really should be updated not
to.

To add a scheme source parameter to a fetch directive, again you can use the
`addFetchPolicy($directive, $policy);` method:

    $csp->addFetchPolicy('style-src' 'https:');

That will add the `https:` parameter to the `style-src` directive, appending it
to any existing directives that may already be there (e.g. `'self'`). It will
remove an existing parameter of `'none'`.

### Unsafe Compatibility Parameters

For compatibility with web applications written with poor coding standards, two
CSP fetch directive policy parameters exist that allow the easy use of inline
`<script>` and `<style>` nodes as well as the very unsafe JavaScript `eval()`
function.

#### The `unsafe-inline` Parameter

This parameter loosens up the CSP default of not allowing for inline
JavaScript. Inline JavaScript is particularly dangerous to allow this way
because the web browser has no way to validate the script it is executing is
actually part of the web application or if it was injected as part for an
[XSS Injection](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))
attack.

To use this very unsafe parameter, you can add it to either the `script-src`
directive or to the `style-src` directive:

    $csp->addFetchPolicy('script-src', 'unsafe-inline');

However it is preferable to use either the
[Matching Hash Source](#matching-hash-source) or the
[Matching Nonce](#matching-nonce) methods described below.

Or you could fix your web application platform to no longer use inline JS/CSS.

#### The `unsafe-eval` Parameter

JavaScript has an `eval()` function that evaluates a string and executes it.
It is considered very dangerous and should not be used in the context of a web
browser where there is absolutely no way to adequately protect the user from
the dangers of the function.

The `eval()` function is part of JavaScript so browsers have to implement it,
but when a web page is served with Content Security Policy the browsers can
refuse to execute scripts that contain it, as they should because there is no
way to validate the source of the string being executed and CSP is about source
validation.

Unfortunately there was whining and for compatibility with web applications
that use `eval()`, a policy parameter was created to allow its continued use.

To add this parameter in this class:

    $csp->addFetchPolicy('script-src', 'unsafe-eval');

This will generate a message to your log files telling you to fix your very
dangerous code.

See [`eval()` - JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval)
on the Mozilla Developer Network for ways to port JS that uses `eval()` to
something both safer and faster.

### Matching Hash Source

In CSP level 2 this was used solely as a secure way to allow inline script and
styles to load. In CSP level 3 it can also be used as a secure way to allow
remote style and script sources to load *without* white-listing the entire
domain the remote resource is hosted on, though honestly the need for that is
probably rare.

To me it is ambiguous as to whether or not this can be used for resources such
as images or media, so this class only allows this parameter to be set in the
`script-src` and `style-src` directives.

Due to the fact that unless a hashing algorithm is broken, a specific hash will
only correspond to one specific file - it did not make sense for me to support
this parameter in the `default-src` directive.

There are two ways to add this parameter, both require that have a suitable
hash of the resource that clients are to allow.

CSP level 3 allows three different algorithm choices, from the
[SHA-2 family](https://en.wikipedia.org/wiki/SHA-2):

* `sha256`
* `sha384`
* `sha512`

CSP level 2 only allows `sha256` and that is actually what I recommend you use,
not just for CSP level 2 compatibility but because the result is a smaller
string. Technically that means a collision (where more than one file has the
same hash) is more likely, but with any of those algorithms, a collision is
only going to occur if the hashing algorithm is broken. So far, there is no
evidence that any hashing algorithms in the SHA-2 family have been broken.

It may ‘feel safer’ to use the longer hashes, but really that is just a human
emotion that bigger is better. All three are sufficiently big enough to resist
a brute force collision attack, an intentional collision will only occur if
they are actually broken.

SHA-2 is susceptible to a length extension attack but that is not relevant to
a digest hash, that involves a cryptography secret that a digest hash simply
does not have.

Anyway I recommend just using `sha256` for a hash source parameter.

The CSP specifications requires the hash be base64 encoded. The class here
will convert a hex encoded hash to base64 for you.

For inline scripts, the hash needs to be a hash of EVERYTHING between the
opening `<script>` tag and the closing `</script>` tag *including* any newline
characters directly after the opening tag or before the closing tag. For
example:

    <script type="application/javascript">
    window.alert('Hello, World!');
    </script>

A hash of that script would be of a string that starts with the newline
directly after `<script type="application/javascript">` and ends with the
newline directly before the `</script>`.

You can generate the hash with the php `hash()` function:

    $myhash = hash('sha256', $string, false);

The variable `$myhash` will now contain a hex encoded string of the hash.

While the class will convert that to base64 for you, if you prefer you can do
it yourself:

    $raw = hash('sha256', $string, true);
    $myhash = base64_enc($raw);

That will result in a base64 encoded hash string instead of hex encoded.

If the string is static, honestly I personally would create an object that
contains the string and the hash and cache it with a PSR-16 cache engine
(such as
[SimpleCacheAPCu](https://github.com/AliceWonderMiscreations/SimpleCacheAPCu) or
[SimpleCacheRedis](https://github.com/AliceWonderMiscreations/SimpleCacheRedis))
so that it the web app does not constantly need to calculate the hash every
time the page is served.

Anyway, when you have the hash, there are two ways to add it as a CSP
parameter.

__Method One: Create The Policy Parameter__

You can create the policy parameter yourself by specifying which of the three
hashing algorithms you used, adding a dash, and then the hash. For example:

    $policyParam = 'sha256-' . $myhash;
    $csp->addFetchPolicy('script-src', $policyParam);

Again it is okay if `$myhash` is hex, the class will convert it for you.

__Method Two: `addScriptHash`__

The second way is to use a public property specifically created for adding a
hash policy parameter, the `addScriptHash(string $algo, string $hash)` method.

The first argument is the algorithm, the second is the hash:

    $csp->addScriptHash('sha256', $myhash);

For the `style-src` directive:

    $csp->addStyleHash('sha256', $myhash);

### Matching Nonce

In the context of Content Security Policy, a nonce is a token that can not be
guessed. It is generated using a cryptographically secure random generator
with a very large field of possible values.

The W3C recommends a 128 bit nonce (16 bytes) and this class enforces that
recommendation, it does not allow the use of a nonce smaller than 128 bits.

The nonce needs to be generated when the page is created, sent with the header,
and then specified in any inline `<script>` or `<style>` nodes as an attribute
to the node. That will let the browser have some certainty that the `<script>`
or `<style>` node is genuine and is not part of a
[XSS](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)) injection.

This class has a static function that will generate a nonce for you:

    public static function generateNonce(int $bytes = 16): string
    {
        if ($bytes < 16) {
            $bytes = 16;
        }
        $random = random_bytes($bytes);
        return base64_encode($random);
    }//end generateNonce()

As you can see, it makes sure the nonce is at least 16 bytes and it uses the
php [`random_bytes`](http://php.net/manual/en/function.random-bytes.php)
function to generate the nonce, which is a cryptographically secure function.
The function returns a base64 encoded string.

Since it is a static function, you can all it before instantiating the class
allowing you to use it in the class constructor:

    use \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy as CSP;
    $nonce = CSP::generateNonce();
    $csp = new CSP('self nonce-' . $nonce);

That will instantiate an instance of the class with a `default-src` directive
that looks something like:

    default-src 'self' 'nonce-MBFAF0mLaOtuUuWKhJM3Tg==';

As long as you do not specify a `script-src` or a `style-src` directive, the
`default-src` parameters will apply to `<script>` and `<style>` nodes, so any
inline `<script>` or `<style>` nodes would just need a `nonce` attribute that
contains the nonce, and the browser would know to trust it is intended:

    <script type="application/javascript" nonce="MBFAF0mLaOtuUuWKhJM3Tg==">
    window.alert('Hello, World!');
    </script>

If you do need to specify custom parameters to `script-src` and/or `style-src`
there are several options.

First, you can copy the `default-src` parameters into them:

    $csp->copyDefaultFetchPolicy('script-src');

That will copy the contents of the `default-src` policy into `script-src`
*replacing anything there* but allowing you to add additional parameters on
top of them (such as additional remote hosts to trust).

The other option is to just set the nonce in the `script-src` or `style-src`
directive directly. There are two ways to do that:

    $policyNonce = 'nonce-' . $nonce;
    $csp->addFetchPolicy('script-src', $policyNonce);

The second way, and the way that I would when starting with an application that
uses inline scripts:

    $csp->addNonce('script-src', $nonce);

### Strict Dynamic

This parameter appears to only apply the the `script-src` directive and then
only when the scripts are trusted because of a hash or a nonce.

It looks like what it does is extend that trust to scripts loaded by that
trusted script rather than validating those loaded scripts.

Sounds kind of dangerous to me, the perfect opportunity for trust to be
exploited.

If you want to use it:

    $csp->addFetchPolicy('script-src', 'strict-dynamic');

### Report Sample Code

This parameter appears to only apply to the `script-src` directive and only
when error reporting is enabled.

It instructs the client to include the portion of the violating JavaScript that
caused a CSP violation in its report about that violation.












Will Not Implement
------------------

The following CSP directives will not be implemented by this class unless I can
be given a very good use case for doing so:

[`block-all-mixed-content`](#the-block-all-mixed-content-directive)
[`referrer`](#the-referrer-directive)


### The `block-all-mixed-content` Directive

This causes the browser to block any HTTP resources when the page is an HTTPS
page. That actually is a good thing, and it really should be the browser
default.

However it is a duplicate function. You can already set the policy for each
fetch type directive to only include secure resources.

### The `referrer` Directive

This allows you to specify information that should be sent with the HTTP
`referer` (sic) header.

It is considered obsolete and should not be used, use the
[`Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
header instead, which is a separate header from CSP.





APPENDIX
========






Inline JavaScript and CSS
-------------------------

With dynamically generated and interactive web pages, inline JS/CSS is a
security risk. The class of attacks that take advantage of inline JS/CSS
are known as
[Cross-Site Scripting](https://en.wikipedia.org/wiki/Cross-site_scripting)
attacks. For this reason, Content Security Policy blocks them by default.

The issue is that it is not possible for the browser to determine whether
inline scripts are legitimate or the result of a code injection.

With JS/CSS in external files, the browser can look at the CSP policy and make
sure they are being served from a source that is allowed, it usually is much
harder for an attacker to upload a malicious script such that it can be used
as an external resource on a domain the security policy allows than it is for
them to find am XSS injection vector.

Obviously the best thing to do is simply not use any inline JavaScript and
CSS and new web applications should be developed that way (jQuery makes it a
lot easier) but porting existing platforms to not use them can be a major
undertaking that can also be expensive.

Rather than deny the ability of websites running those platforms to use CSP,
some solutions have been created. Three specifically that I will mention here.

### The `unsafe-inline` Policy

I only mention this method because it exists. It is the most dangerous way to
allow inline scripting with Content Security Policy. I suppose it is better
than not using CSP at all, but it violates one of the most fundamental rules of
security, it trusts without verifying.

I do not recommend doing this, and it seems to not always work. Reports are
that recent versions of FireFox and Chrome still block inline scripts under
certain conditions when CSP is used with this directive. I have not verified
myself and really do not care too, it's dangerous and there are better ways.

### The `nonce` Method

If I needed to run inline scripts, this is how I probably would do it. When
your web application generates a page, it creates what is called a nonce.

A nonce is a single use token that expires as soon as it is used. The nonce
is sent as part of the CSP header, and then CSP allows inline scripts that
specify that nonce.

The W3C recommends that the nonce be at least 128 bits (16 bytes) and generated
with a cryptographically secure random number generator. The php `rand()`
function is not good enough, for example. Fortunately PHP 7 has `random_bytes()
which is cryptographically secure and safe to use to generate a nonce for this
purpose.

The `generateNonce()` static method in this class will produce a suitable
16-byte nonce using the proper cryptographically random generator, and you can
then use it as a nonce with this class. For example:

    use \AWonderPHP\ContentSecurityPolicy\ContentSecurityPolicy as CSP;
    $nonce = CSP::generateNonce();
    $csp = new CSP('self');
    $csp->addNonce('script-src', $nonce);
    $csp->sendCspHeader();

In the generation of the page, everywhere your code intentionally ads an
inline script node, just make sure it has the following:

    <script nonce="$nonce">window.alert("I am an inline script!");</script>

Since the `nonce` attribute will match the nonce sent in the CSP header, your
browser now has a means by which to verify with some degree of confidence that
the inline script is okay to execute. It has been validated as intentional.

#### Do Not Use `unsafe-inline` and a nonce together

__NOTE:__ There is some advice out there to use both the `unsafe-inline` and
the nonce method. That is crusty outdated advice. This class does not allow
both at the same time. If you specify a nonce as part of a `script-src` or
`style-src` policy, `unsafe-inline` is removed from that directive.

CSP level 2 and 3 browsers ignore `unsafe-inline` when a nonce is declared, so
the presence of the `unsafe-inline` directive when a nonce is there is only of
benefit to very old browsers, but it creates an opportunity for a downgrade
attack. If an attacker is able to influence a browser to ignore the presence of
the nonce directive that provides actual validation then the browser would
allow the `unsafe-inline` directive that does no validation. So it is safer to
__NOT__ allow `unsafe-inline` when a nonce is used.

#### Nonce Security Holes

__NOTE:__ Even with a nonce, XSS script injection is still possible. To see
more information on how, the
[W3C documentation](https://w3c.github.io/webappsec-csp/#security-considerations)
does a really good job at explaining.

### The SHA-2 Method

An even more robust method of securing inline scripts is to send a SHA-2 hash
of inline scripts as part of the CSP header.


The `frame-src`, `child-src`, and `worker-src` Directives
---------------------------------------------------------

CSP level 1 had a directive called `frame-src` that was used to define rules
about what could be loaded in `<frame>` and `<iframe>` tags. CSP 1 did not any
directives to cover [web workers](https://en.wikipedia.org/wiki/Web_worker).

In CSP level 2, they deprecated `frame-src` in favor of a directive called
`child-src` that covered web workers as well. When a resource that was either
a frame or web worker resource needed to be checked, CSP 2.0 implementing first
would look for the `child-src` policy, and if that did not exist they would see
if the deprecated `frame-src` policy was defined, and finally use `default-src`
as the final fall-back.

Using a single policy for both frames and web workers really was not a great
idea, they are different and often served from different places, they really
did need different policies.

So CSP level 3 (not yet finalized) is deprecating `child-src`, un-deprecating
`frame-src` and introducing `worker-src`. Browsers implementing it (and some
already are) will use `child-src` as a fallback for those two if they are not
defined before using `default-src`.

It's the right thing to do, but it creates an implementation issue.

Browsers that only implement CSP level 2 will ignore `worker-src` and sites
that do not have a `child-src` directive defined to cover web workers very
well may break in some browsers. So web applications will need to have both
a `worker-src` and a `child-src` directive defined for their web workers to
work everywhere.

However since `child-src` takes precedence over `frame-src` in CSP level 2
browsers but is a fall-back to both `frame-src` and `worker-src` in CSP level 3
browsers, it is possible for unintended consequences.

Nutshell, the `child-src` directive needs to be a hybrid of both `frame-src`
and `worker-src` in order for the CSP level 2 browsers to work, but to prevent
it from providing unintended rules in CSP level 3 browsers when either
`frame-src` or `worker-src` are not defined, it is critical to make sure that
if either of those are not defined, they will be defined with the `default-src`
policy instead of the `child-src` policy.

Hybridizing the `frame-src` and `worker-src` into a `child-src` that works with
CSP level 2 browsers is *crudely* done right now. Most use case scenarios it
will work but I can think of a few cases where it will not. I will improve
that.

Making sure the `child-src` directive this class manufacturers does not
interfere with CSP level 3 browsers when `frame-src` or `worker-src` is not
defined is done. The `child-src` directive will be present if one or the other
is defined, but in cases where CSP level 3 browsers would fall back to
`default-src` for the definitions in the absence of `child-src`, the
`default-src` definitions are explicitly used with `frame-src` or `worker-src`
to prevent that.
























