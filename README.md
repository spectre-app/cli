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

The source is broken down into several components, each hosted in their own repository. Submodules are used to correlate dependencies.

 - [api](https://gitlab.com/spectre.app/api): The algorithm's reference implementation and API library.  There is a C, Java and W3C interface.
 - [cli](https://gitlab.com/spectre.app/cli): The official command-line interface for POSIX systems.
 - [desktop](https://gitlab.com/spectre.app/desktop): The official cross-platform desktop application.
 - [macos](https://gitlab.com/spectre.app/macos): The official Apple macOS desktop application.
 - [ios](https://gitlab.com/spectre.app/ios): The official Apple iOS mobile application.
 - [android](https://gitlab.com/spectre.app/android): The official Google Android mobile application.
 - [web](https://gitlab.com/spectre.app/web): The official cross-platform web application.
 - [www](https://gitlab.com/spectre.app/www): The Spectre homepage.


## Building

This repository hosts the POSIX command-line interface.

To build the code to run on your specific system, run the `build` script:

    ./build

Note that the build depends on your system having certain dependencies already installed.
By default, you'll need to have at least `libsodium`, `libjson-c` and `libncurses` installed.
Missing dependencies will be indicated by the script.

### Details

The build script comes with a default configuration which can be adjusted.  Full details on the build script are available by opening the build script file.

    [targets='...'] [spectre_feature=0|1 ...] [CFLAGS='...'] [LDFLAGS='...'] ./build [cc arguments ...]

By default, the build script only builds the `spectre` target.  You can specify other targets or `all` to build all available targets.  These are the currently available targets:

 - `spectre`        : The main app.  Options: needed: `spectre_sodium`, optional: `spectre_color`, `spectre_json`.
 - `spectre-bench`  : A benchmark utility.  Options: needed: `spectre_sodium`.
 - `spectre-tests`  : An algorithm test suite.  Options: needed: `spectre_sodium`, `spectre_xml`.

It is smart to build the test suite along with the app, eg.:

    targets='spectre spectre-tests' ./build

The options determine the dependencies that the build will require.  The following exist:

 - `spectre_sodium` : Use Sodium for the crypto implementation.  It needs libsodium.
 - `spectre_json`   : Support JSON-based user configuration format.  It needs libjson-c.
 - `spectre_color`  : Use advanced terminal support for input/output.  It needs libcurses/libtinfo.
 - `spectre_xml`    : Support XML parsing.  It needs libxml2.

By default, all options are enabled.  Each option can be disabled or enabled explicitly by prefixing the build command with an assignment of it to `0` or `1`, eg.:

    spectre_color=0 ./build

As a result of this command, you'd build the `spectre` target (which supports a `spectre_color` flag), but with color support turned off.  The build no longer requires a terminal library but the resulting `spectre` binary will not have support for advanced terminal features such as colorized identicons or silent dialog-based input, falling back to the most basic POSIX input/output mechanisms.

You can also pass CFLAGS or LDFLAGS to the build, or extra custom compiler arguments as arguments to the build script.
For instance, to add a custom library search path, you could use:

    LDFLAGS='-L/usr/local/lib' ./build


### Alternative: cmake

There is also a cmake configuration you can use to build instead of using the `./build` script.  While `./build` depends on Bash and is geared toward POSIX systems, cmake is platform-independent.  You should use your platform's cmake tools to continue.  On POSIX systems, you should be able to use:

    cmake . && make

To get a list of options supported by the cmake configuration, use:

    cmake -LH

Options can be toggled like so:

    cmake -DUSE_COLOR=OFF -DBUILD_SPECTRE_TESTS=ON . && make

## Testing

Once the client is built, you should run a test suite to make sure everything works as intended.

There are currently two test programs:

 - `spectre-tests`     : Tests the algorithm implementation.
 - `spectre-cli-tests` : Tests the CLI application.

The `spectre-tests` program is only available if you enabled its target during build (see "Details" above).

The `spectre-cli-tests` is a Bash shell script, hence depends on your system having Bash available.


## Installing

Once you're happy with the result, you can install the `spectre` application into your system's `PATH`.

Generally, all you need to do is copy the `spectre` file into a PATH directory, eg.:

    cp spectre /usr/local/bin/

The directory that you should copy the `spectre` file into will depend on your system.  Also note that `cp` is a POSIX command, if your system is not a POSIX system (eg. Windows) you'll need to adjust accordingly.

There is also an `install` script to help with this process, though it is a Bash script and therefore requires that you have Bash installed:

    ./install

After installing, you should be able to run `spectre` and use it from anywhere in the terminal:

    spectre -h
    spectre google.com

