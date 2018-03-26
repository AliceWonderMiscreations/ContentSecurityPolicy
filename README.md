ContentSecurityPolicy
=====================

__THIS CLASS IS NOT YET READY FOR USE__

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

The CSP header is basically a serialized array of directives, which each
directive specifying a set of policies specific to that directive.

### Policy Directives

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


AWonderPHP CSP Class Implementation
-----------------------------------

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
























