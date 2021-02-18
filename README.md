# [Spectre](https://spectre.app)

Spectre introduces a completely new way of thinking about passwords.

[[_TOC_]]


## Don't store; derive

Every attempt to solve the problem of passwords by means of storing countless unique site-specific tokens inevitably leads to complexity, loss of control, and security compromise.

Spectre flips the problem on its head by rejecting the notion of statefulness and giving the user a single secret to remember.  The Spectre algorithm then derives whatever secret tokens you need.

    site-password = SPECTRE( user-name, user-secret, site-name )


## How does it work?

In short (simplified):

    user-key = SCRYPT( user-name, user-secret )
    site-key = HMAC-SHA-256( site-name . site-counter, user-key )
    site-password = PW( site-template, site-key )

Consequently, Spectre can derive any `site-password` given the necessary base ingredients (ie. the `user-name`, `user-secret`, `site-name`, `site-counter` and `site-template`).

As an example:

    user-name = Robert Lee Mitchell
    user-secret = banana colored duckling
    site-name = twitter.com
    site-counter = 1
    site-template = Long Password
    site-password = PozoLalv0_Yelo

We standardize `user-name` as your full legal name, `site-name` as the domain name that hosts the site, `site-counter` to `1` (unless you explicitly increment it) and `site-template` to `Long Password`; as a result the only token the user really needs to remember is their `user-secret`.


# Source Code

Spectre's algorithm and implementation is fully documented and licensed Free Software under the (GPLv3)[LICENSE].


## Components

The source is broken down into several components:

 - [api](https://gitlab.com/spectre.app/api): The algorithm's reference implementation and API library.  There is a C, Java and W3C interface.
 - [cli](https://gitlab.com/spectre.app/cli): The official command-line interface for POSIX systems.
 - [desktop](https://gitlab.com/spectre.app/desktop): The official cross-platform desktop application.
 - [macos](https://gitlab.com/spectre.app/macos): The official Apple macOS desktop application.
 - [ios](https://gitlab.com/spectre.app/ios): The official Apple iOS mobile application.
 - [android](https://gitlab.com/spectre.app/android): The official Google Android mobile application.
 - [web](https://gitlab.com/spectre.app/web): The official cross-platform web application.
 - [www](https://gitlab.com/spectre.app/www): The Spectre homepage.


## Building and running

This repository hosts a Hugo static site.

Build using:


```
$ hugo
```

The site should be available at `public/index.html`.
