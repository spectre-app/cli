//==============================================================================
// This file is part of Spectre.
// Copyright (c) 2011-2017, Maarten Billemont.
//
// Spectre is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Spectre is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You can find a copy of the GNU General Public License in the
// LICENSE file.  Alternatively, see <http://www.gnu.org/licenses/>.
//==============================================================================

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sysexits.h>

#include "spectre-cli-util.h"
#include "spectre-algorithm.h"
#include "spectre-util.h"
#include "spectre-marshal.h"
#include "spectre-marshal-util.h"

/** Output the program's usage documentation. */
static void usage() {

    inf( ""
         "  Spectre v%s - CLI\n"
         "--------------------------------------------------------------------------------\n"
         "      https://spectre.app\n", stringify_def( Spectre_VERSION ) );
    inf( ""
         "\nUSAGE\n\n"
         "  spectre [-u|-U user-name] [-s fd] [-t pw-type] [-P value] [-c counter]\n"
         "      [-a version] [-p purpose] [-C context] [-f|F format] [-R 0|1]\n"
         "      [-v|-q]* [-n] [-h] [site-name]\n" );
    inf( ""
         "  -u user-name Specify the user name of the user.\n"
         "               -u checks the personal secret against the config,\n"
         "               -U allows updating to a new personal secret.\n"
         "               Defaults to %s in env or prompts.\n", Spectre_ENV_userName );
    inf( ""
         "  -s fd        Read the personal secret of the user from a file descriptor.\n"
         "               Tip: don't send extra characters like newlines such as by using\n"
         "               echo in a pipe.  Consider printf instead.\n" );
    dbg( ""
         "  -S secret    Specify the personal secret of the user.\n"
         "               Passing secrets as arguments is unsafe, for use in testing only." );
    inf( ""
         "  -t pw-type   Specify the password's template.\n"
         "               Defaults to 'long' (-p a), 'name' (-p i) or 'phrase' (-p r).\n"
         "                   x, maximum  | 20 characters, contains symbols.\n"
         "                   l, long     | Copy-friendly, 14 characters, symbols.\n"
         "                   m, medium   | Copy-friendly, 8 characters, symbols.\n"
         "                   b, basic    | 8 characters, no symbols.\n"
         "                   s, short    | Copy-friendly, 4 characters, no symbols.\n"
         "                   i, pin      | 4 numbers.\n"
         "                   n, name     | 9 letter name.\n"
         "                   p, phrase   | 20 character sentence.\n"
         "                   K, key      | encryption key (512 bit or -P bits).\n"
         "                   P, personal | saved personal password (save with -P pw).\n" );
    inf( ""
         "  -P value     The parameter value.\n"
         "                   -p i        | The login name for the site.\n"
         "                   -t K        | The bit size of the key to generate (eg. 256).\n"
         "                   -t P        | The personal password to encrypt.\n" );
    inf( ""
         "  -c counter   The value of the counter.\n"
         "               Defaults to 1.\n" );
    inf( ""
         "  -a version   The algorithm version to use, %d - %d.\n"
         "               Defaults to env var %s or %d.\n",
            SpectreAlgorithmFirst, SpectreAlgorithmLast, Spectre_ENV_algorithm, SpectreAlgorithmCurrent );
    inf( ""
         "  -p purpose   The purpose of the generated token.\n"
         "               Defaults to 'auth'.\n"
         "                   a, auth     | An authentication token such as a password.\n"
         "                   i, ident    | An identification token such as a username.\n"
         "                   r, rec      | A recovery token such as a security answer.\n" );
    inf( ""
         "  -C context   A purpose-specific context.\n"
         "               Defaults to empty.\n"
         "                   -p a        | -\n"
         "                   -p i        | -\n"
         "                   -p r        | Most significant word in security question.\n" );
    inf( ""
         "  -f|F format  The file format to use for reading/writing user state.\n"
         "               -f reads the given format, allows fall-back & writes the default format (%s).\n"
         "               -F reads & writes only the given format,\n"
         "               Defaults to env var %s or the default format (%s).\n"
         "                   n, none     | No file\n"
         "                   f, flat     | ~/.spectre.d/user-name.%s\n"
         "                   j, json     | ~/.spectre.d/user-name.%s\n",
            spectre_format_name( SpectreFormatDefault ), Spectre_ENV_format, spectre_format_name( SpectreFormatDefault ),
            spectre_format_extension( SpectreFormatFlat ), spectre_format_extension( SpectreFormatJSON ) );
    inf( ""
         "  -R redacted  Whether to save the file in redacted format or not.\n"
         "               Redaction omits or encrypts any secrets, making the file safe\n"
         "               for saving on or transmitting via untrusted media.\n"
         "               Defaults to 1, redacted.\n" );
    inf( ""
         "  -v           Increase output verbosity (can be repeated).\n"
         "  -q           Decrease output verbosity (can be repeated).\n" );
    inf( ""
         "  -n           Omit trailing newline in output.\n" );
    inf( ""
         "  -h           Show this help output instead of performing any operation.\n" );
    inf( ""
         "  site-name    Name of the site for which to generate a token.\n" );
    inf( ""
         "\nENVIRONMENT\n\n"
         "  %-12s The user name of the user (see -u).\n"
         "  %-12s The default algorithm version (see -a).\n"
         "  %-12s The default file format (see -f).\n"
         "  %-12s The askpass program to use for prompting the user.\n",
            Spectre_ENV_userName, Spectre_ENV_algorithm, Spectre_ENV_format, Spectre_ENV_askpass );
    exit( EX_OK );
}

// Internal state.

typedef struct {
    const char *userName;
    const char *userSecretFD;
    const char *userSecret;
    const char *siteName;
    const char *resultType;
    const char *resultParam;
    const char *keyCounter;
    const char *keyPurpose;
    const char *keyContext;
    const char *algorithmVersion;
    const char *fileFormat;
    const char *fileRedacted;
} Arguments;

typedef struct {
    bool omitNewline;
    bool allowPasswordUpdate;
    bool fileFormatFixed;
    SpectreFormat fileFormat;
    const char *filePath;
    const char *userName;
    const char *userSecret;
    const char *identicon;
    const char *siteName;
    SpectreResultType resultType;
    const char *resultState;
    const char *resultParam;
    const char *resultPurpose;
    SpectreCounter keyCounter;
    SpectreKeyPurpose keyPurpose;
    const char *keyContext;
    SpectreAlgorithm algorithm;
    SpectreMarshalledFile *file;
    SpectreMarshalledUser *user;
    SpectreMarshalledSite *site;
    SpectreMarshalledQuestion *question;
} Operation;

// Processing steps.

void cli_free(Arguments *args, Operation *operation);
void cli_args(Arguments *args, Operation *operation, const int argc, char *const argv[]);
void cli_userName(Arguments *args, Operation *operation);
void cli_userSecret(Arguments *args, Operation *operation);
void cli_siteName(Arguments *args, Operation *operation);
void cli_fileFormat(Arguments *args, Operation *operation);
void cli_keyCounter(Arguments *args, Operation *operation);
void cli_keyPurpose(Arguments *args, Operation *operation);
void cli_keyContext(Arguments *args, Operation *operation);
void cli_user(Arguments *args, Operation *operation);
void cli_site(Arguments *args, Operation *operation);
void cli_question(Arguments *args, Operation *operation);
void cli_resultType(Arguments *args, Operation *operation);
void cli_resultState(Arguments *args, Operation *operation);
void cli_resultParam(Arguments *args, Operation *operation);
void cli_algorithmVersion(Arguments *args, Operation *operation);
void cli_fileRedacted(Arguments *args, Operation *operation);
void cli_spectre(Arguments *args, Operation *operation);
void cli_save(Arguments *args, Operation *operation);

SpectreKeyProvider spectre_proxy_provider_set_operation(Operation *operation);

/** ========================================================================
 *  MAIN                                                                     */
int main(const int argc, char *const argv[]) {

    // Application defaults.
    Arguments args = {
            .userName = spectre_getenv( Spectre_ENV_userName ),
            .algorithmVersion = spectre_getenv( Spectre_ENV_algorithm ),
            .fileFormat = spectre_getenv( Spectre_ENV_format ),
    };
    Operation operation = {
            .allowPasswordUpdate = false,
            .fileFormatFixed = false,
            .fileFormat = SpectreFormatDefault,
            .resultType = SpectreResultDefaultResult,
            .keyCounter = SpectreCounterDefault,
            .keyPurpose = SpectreKeyPurposeAuthentication,
    };

    // Read the command-line options.
    cli_args( &args, &operation, argc, argv );

    // Determine the operation parameters not sourced from the user's file.
    cli_userName( &args, &operation );
    cli_userSecret( &args, &operation );
    cli_siteName( &args, &operation );
    cli_fileFormat( &args, &operation );
    cli_keyPurpose( &args, &operation );
    cli_keyContext( &args, &operation );

    // Load the operation parameters present in the user's file.
    cli_user( &args, &operation );
    cli_site( &args, &operation );
    cli_question( &args, &operation );

    // Override the operation parameters from command-line arguments.
    cli_algorithmVersion( &args, &operation );
    cli_resultType( &args, &operation );
    cli_resultState( &args, &operation );
    cli_resultParam( &args, &operation );
    cli_keyCounter( &args, &operation );
    cli_fileRedacted( &args, &operation );
    cli_free( &args, NULL );

    // Operation summary.
    dbg( "-----------------" );
    if (operation.file && operation.user) {
        dbg( "userName         : %s", operation.user->userName );
        dbg( "identicon        : %s", operation.identicon );
        dbg( "fileFormat       : %s%s", spectre_format_name( operation.fileFormat ), operation.fileFormatFixed? " (fixed)": "" );
        dbg( "filePath         : %s", operation.filePath );
    }
    if (operation.site) {
        dbg( "siteName         : %s", operation.siteName );
        dbg( "resultType       : %s (%u)", spectre_type_short_name( operation.resultType ), operation.resultType );
        dbg( "resultParam      : %s", operation.resultParam );
        dbg( "keyCounter       : %u", operation.keyCounter );
        dbg( "keyPurpose       : %s (%u)", spectre_purpose_name( operation.keyPurpose ), operation.keyPurpose );
        dbg( "keyContext       : %s", operation.keyContext );
        dbg( "algorithmVersion : %u", operation.algorithm );
    }
    dbg( "-----------------" );

    // Finally ready to perform the actual operation.
    cli_spectre( NULL, &operation );

    // Save changes and clean up.
    cli_save( NULL, &operation );
    cli_free( NULL, &operation );

    return EX_OK;
}

void cli_free(Arguments *args, Operation *operation) {

    if (args) {
        spectre_free_strings( &args->userName, &args->userSecretFD, &args->userSecret, &args->siteName, NULL );
        spectre_free_strings( &args->resultType, &args->resultParam, &args->keyCounter, &args->algorithmVersion, NULL );
        spectre_free_strings( &args->keyPurpose, &args->keyContext, &args->fileFormat, &args->fileRedacted, NULL );
    }

    if (operation) {
        spectre_free_strings( &operation->userName, &operation->userSecret, &operation->siteName, NULL );
        spectre_free_strings( &operation->keyContext, &operation->resultState, &operation->resultParam, NULL );
        spectre_free_strings( &operation->identicon, &operation->filePath, NULL );
        spectre_marshal_file_free( &operation->file );
        spectre_marshal_user_free( &operation->user );
        operation->site = NULL;
        operation->question = NULL;
        spectre_proxy_provider_unset();
    }
}

void cli_args(Arguments *args, Operation *operation, const int argc, char *const argv[]) {

    for (int opt; (opt = getopt( argc, argv, "u:U:s:S:t:P:c:a:p:C:f:F:R:vqnh" )) != EOF;
         optarg? spectre_zero( optarg, strlen( optarg ) ): (void)0)
        switch (opt) {
            case 'u':
                args->userName = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                operation->allowPasswordUpdate = false;
                break;
            case 'U':
                args->userName = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                operation->allowPasswordUpdate = true;
                break;
            case 's':
                args->userSecretFD = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                break;
            case 'S':
                // Passing your personal secret via the command-line is insecure.  Testing purposes only.
                args->userSecret = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                break;
            case 't':
                args->resultType = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                break;
            case 'P':
                args->resultParam = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                break;
            case 'c':
                args->keyCounter = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                break;
            case 'a':
                args->algorithmVersion = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                break;
            case 'p':
                args->keyPurpose = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                break;
            case 'C':
                args->keyContext = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                break;
            case 'f':
                args->fileFormat = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                operation->fileFormatFixed = false;
                break;
            case 'F':
                args->fileFormat = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                operation->fileFormatFixed = true;
                break;
            case 'R':
                args->fileRedacted = optarg && strlen( optarg )? spectre_strdup( optarg ): NULL;
                break;
            case 'v':
                ++spectre_verbosity;
                break;
            case 'q':
                --spectre_verbosity;
                break;
            case 'n':
                operation->omitNewline = true;
                break;
            case 'h':
                usage();
                break;
            case '?':
                switch (optopt) {
                    case 'u':
                        ftl( "Missing user name to option: -%c", optopt );
                        exit( EX_USAGE );
                    case 't':
                        ftl( "Missing type name to option: -%c", optopt );
                        exit( EX_USAGE );
                    case 'c':
                        ftl( "Missing counter value to option: -%c", optopt );
                        exit( EX_USAGE );
                    default:
                        ftl( "Unknown option: -%c", optopt );
                        exit( EX_USAGE );
                }
            default:
                ftl( "Unexpected option: %c", opt );
                exit( EX_USAGE );
        }

    if (optind < argc && argv[optind])
        args->siteName = spectre_strdup( argv[optind] );
}

void cli_userName(Arguments *args, Operation *operation) {

    spectre_free_string( &operation->userName );

    if (args->userName)
        operation->userName = spectre_strdup( args->userName );

    if (!operation->userName || !strlen( operation->userName ))
        do {
            operation->userName = spectre_getline( "Your full name:" );
        } while (operation->userName && !strlen( operation->userName ));

    if (!operation->userName || !strlen( operation->userName )) {
        ftl( "Missing full name." );
        cli_free( args, operation );
        exit( EX_DATAERR );
    }
}

void cli_userSecret(Arguments *args, Operation *operation) {

    spectre_free_string( &operation->userSecret );

    if (args->userSecretFD) {
        operation->userSecret = spectre_read_fd( (int)strtol( args->userSecretFD, NULL, 10 ) );
        if (!operation->userSecret && errno)
            wrn( "Error reading personal secret from FD %s: %s", args->userSecretFD, strerror( errno ) );
    }

    if (args->userSecret && !operation->userSecret)
        operation->userSecret = spectre_strdup( args->userSecret );

    if (!operation->userSecret || !strlen( operation->userSecret ))
        do {
            operation->userSecret = spectre_getpass( "Your personal secret: " );
        } while (operation->userSecret && !strlen( operation->userSecret ));

    if (!operation->userSecret || !strlen( operation->userSecret )) {
        ftl( "Missing personal secret." );
        cli_free( args, operation );
        exit( EX_DATAERR );
    }
}

void cli_siteName(Arguments *args, Operation *operation) {

    spectre_free_string( &operation->siteName );

    if (args->siteName)
        operation->siteName = spectre_strdup( args->siteName );
    if (!operation->siteName)
        operation->siteName = spectre_getline( "Site Domain:" );

    if (!operation->siteName) {
        ftl( "Missing site name." );
        cli_free( args, operation );
        exit( EX_DATAERR );
    }
}

void cli_fileFormat(Arguments *args, Operation *operation) {

    if (!args->fileFormat)
        return;

    operation->fileFormat = spectre_format_named( args->fileFormat );
    if (ERR == (int)operation->fileFormat) {
        ftl( "Invalid file format: %s", args->fileFormat );
        cli_free( args, operation );
        exit( EX_DATAERR );
    }
}

void cli_keyPurpose(Arguments *args, Operation *operation) {

    if (!args->keyPurpose)
        return;

    operation->keyPurpose = spectre_purpose_named( args->keyPurpose );
    if (ERR == (int)operation->keyPurpose) {
        ftl( "Invalid purpose: %s", args->keyPurpose );
        cli_free( args, operation );
        exit( EX_DATAERR );
    }
}

void cli_keyContext(Arguments *args, Operation *operation) {

    if (!args->keyContext)
        return;

    operation->keyContext = spectre_strdup( args->keyContext );
}

static FILE *cli_user_open(const SpectreFormat format, Operation *operation) {

    FILE *userFile = NULL;
    size_t count = 0;
    const char **extensions = spectre_format_extensions( format, &count );
    for (int e = 0; !userFile && e < count; ++e) {
        spectre_free_string( &operation->filePath );
        operation->filePath = spectre_path( operation->userName, extensions[e] );

        if (!operation->filePath || !(userFile = fopen( operation->filePath, "r" )))
            dbg( "Couldn't open configuration file:\n  %s: %s", operation->filePath, strerror( errno ) );
    }
    spectre_free( &extensions, count * sizeof( *extensions ) );

    return userFile;
}

void cli_user(Arguments *args, Operation *operation) {

    // Find the user's file from parameters.
    FILE *userFile = cli_user_open( operation->fileFormat, operation );
    if (!userFile && !operation->fileFormatFixed)
        for (SpectreFormat format = SpectreFormatLast; !userFile && format >= SpectreFormatFirst; --format)
            userFile = cli_user_open( format, operation );

    if (!userFile) {
        // If no user from the user's file, create a new one.
        spectre_free_string( &operation->filePath );
        spectre_marshal_file_free( &operation->file );
        spectre_marshal_user_free( &operation->user );
        operation->file = spectre_marshal_file( NULL, NULL, NULL );
        operation->user = spectre_marshal_user( operation->userName, spectre_proxy_provider_set_operation( operation ), SpectreAlgorithmCurrent );
    }

    else {
        // Load the user object from the user's file.
        const char *fileInputData = spectre_read_file( userFile );
        if (!fileInputData || ferror( userFile ))
            wrn( "Error while reading configuration file:\n  %s: %d", operation->filePath, ferror( userFile ) );
        fclose( userFile );

        // Parse file.
        spectre_marshal_file_free( &operation->file );
        spectre_marshal_user_free( &operation->user );
        operation->file = spectre_marshal_read( NULL, fileInputData );
        if (operation->file && operation->file->error.type == SpectreMarshalSuccess) {
            operation->user = spectre_marshal_auth( operation->file, spectre_proxy_provider_set_operation( operation ) );

            if (operation->file->error.type == SpectreMarshalErrorUserSecret && operation->allowPasswordUpdate) {
                // Update personal secret in the user's file.
                while (operation->file->error.type == SpectreMarshalErrorUserSecret) {
                    inf( "Given personal secret does not match configuration." );
                    inf( "To update the configuration with this new personal secret, first confirm the old personal secret." );

                    const char *importUserSecret = NULL;
                    while (!importUserSecret || !strlen( importUserSecret )) {
                        spectre_free_string( &importUserSecret );
                        importUserSecret = spectre_getpass( "Old personal secret: " );
                    }

                    spectre_marshal_user_free( &operation->user );
                    operation->user = spectre_marshal_auth( operation->file, spectre_proxy_provider_set_secret( importUserSecret ) );
                    if (operation->file && operation->user)
                        operation->user->userKeyProvider = spectre_proxy_provider_set_operation( operation );
                    spectre_free_string( &importUserSecret );
                }
            }
        }
        spectre_free_string( &fileInputData );

        // Incorrect personal secret.
        if (operation->file->error.type == SpectreMarshalErrorUserSecret) {
            ftl( "Incorrect personal secret according to configuration:\n  %s: %s", operation->filePath, operation->file->error.message );
            cli_free( args, operation );
            exit( EX_DATAERR );
        }

        // Any other parse error.
        if (!operation->file || !operation->user || operation->file->error.type != SpectreMarshalSuccess) {
            err( "Couldn't parse configuration file:\n  %s: %s", operation->filePath, operation->file->error.message );
            cli_free( args, operation );
            exit( EX_DATAERR );
        }
    }

    if (operation->userSecret)
        operation->user->identicon = spectre_identicon( operation->user->userName, operation->userSecret );
    spectre_free_string( &operation->identicon );
    operation->identicon = spectre_identicon_render( operation->user->identicon );
}

void cli_site(Arguments *args, Operation *operation) {

    if (!operation->siteName)
        abort();

    // Load the site object from the user's file.
    SpectreMarshalledUser *user = operation->user;
    for (size_t s = 0; !operation->site && s < user->sites_count; ++s)
        if (strcmp( operation->siteName, (&user->sites[s])->siteName ) == OK)
            operation->site = &user->sites[s];

    // If no site from the user's file, create a new one.
    if (!operation->site)
        operation->site = spectre_marshal_site(
                user, operation->siteName, user->defaultType, SpectreCounterDefault, user->algorithm );
}

void cli_question(Arguments *args, Operation *operation) {

    if (!operation->site)
        abort();

    // Load the question object from the user's file.
    switch (operation->keyPurpose) {
        case SpectreKeyPurposeAuthentication:
        case SpectreKeyPurposeIdentification:
            break;
        case SpectreKeyPurposeRecovery:
            for (size_t q = 0; !operation->question && q < operation->site->questions_count; ++q)
                if (operation->keyContext == (&operation->site->questions[q])->keyword ||
                    (!operation->keyContext && !strlen( (&operation->site->questions[q])->keyword )) ||
                    (!(&operation->site->questions[q])->keyword && !strlen( operation->keyContext )) ||
                    ((operation->keyContext && (&operation->site->questions[q])->keyword) &&
                     strcmp( (&operation->site->questions[q])->keyword, operation->keyContext ) == OK))
                    operation->question = &operation->site->questions[q];

            // If no question from the user's file, create a new one.
            if (!operation->question)
                operation->question = spectre_marshal_question( operation->site, operation->keyContext );
            break;
    }
}

void cli_resultType(Arguments *args, Operation *operation) {

    if (!operation->site)
        abort();

    switch (operation->keyPurpose) {
        case SpectreKeyPurposeAuthentication: {
            operation->resultPurpose = "site password";
            operation->resultType = operation->site->resultType;
            operation->algorithm = operation->site->algorithm;
            break;
        }
        case SpectreKeyPurposeIdentification: {
            operation->resultPurpose = "site login";
            operation->resultType = operation->site->loginType;
            operation->algorithm = operation->site->algorithm;
            break;
        }
        case SpectreKeyPurposeRecovery: {
            operation->resultPurpose = "site answer";
            operation->resultType = operation->question->type;
            operation->algorithm = operation->site->algorithm;
            break;
        }
    }

    if (!args->resultType)
        return;

    operation->resultType = spectre_type_named( args->resultType );
    if (ERR == (int)operation->resultType) {
        ftl( "Invalid type: %s", args->resultType );
        cli_free( args, operation );
        exit( EX_USAGE );
    }

    if (!(operation->resultType & SpectreResultFeatureAlternate)) {
        switch (operation->keyPurpose) {
            case SpectreKeyPurposeAuthentication:
                operation->site->resultType = operation->resultType;
                break;
            case SpectreKeyPurposeIdentification:
                operation->site->loginType = operation->resultType;
                break;
            case SpectreKeyPurposeRecovery:
                operation->question->type = operation->resultType;
                break;
        }
    }
}

void cli_resultState(Arguments *args, Operation *operation) {

    if (!operation->site)
        abort();

    switch (operation->keyPurpose) {
        case SpectreKeyPurposeAuthentication: {
            operation->resultState = operation->site->resultState? spectre_strdup( operation->site->resultState ): NULL;
            operation->keyCounter = operation->site->counter;
            break;
        }
        case SpectreKeyPurposeIdentification: {
            if (operation->resultType != SpectreResultNone) {
                operation->resultState = operation->site->loginState? spectre_strdup( operation->site->loginState ): NULL;
                operation->keyCounter = SpectreCounterInitial;
            }
            else {
                // Identification at site-level is none, fall back to user-level.
                operation->resultPurpose = "global login";
                spectre_free_string( &operation->siteName );
                operation->siteName = spectre_strdup( operation->user->userName );
                operation->resultType = operation->user->loginType;
                operation->resultState = operation->user->loginState? spectre_strdup( operation->user->loginState ): NULL;
                operation->keyCounter = SpectreCounterInitial;
                operation->algorithm = operation->user->algorithm;
            }
            break;
        }
        case SpectreKeyPurposeRecovery: {
            operation->resultState = operation->question->state? spectre_strdup( operation->question->state ): NULL;
            operation->keyCounter = SpectreCounterInitial;
            spectre_free_string( &operation->keyContext );
            operation->keyContext = operation->question->keyword? spectre_strdup( operation->question->keyword ): NULL;
            break;
        }
    }
}

void cli_keyCounter(Arguments *args, Operation *operation) {

    if (!args->keyCounter)
        return;
    if (!operation->site)
        abort();

    long long int keyCounterInt = strtoll( args->keyCounter, NULL, 0 );
    if (keyCounterInt < SpectreCounterFirst || keyCounterInt > SpectreCounterLast) {
        ftl( "Invalid counter: %s", args->keyCounter );
        cli_free( args, operation );
        exit( EX_USAGE );
    }

    switch (operation->keyPurpose) {
        case SpectreKeyPurposeAuthentication:
            operation->keyCounter = operation->site->counter = (SpectreCounter)keyCounterInt;
            break;
        case SpectreKeyPurposeIdentification:
        case SpectreKeyPurposeRecovery:
            // NOTE: counter for login & question is not persisted.
            break;
    }
}

void cli_resultParam(Arguments *args, Operation *operation) {

    if (!args->resultParam)
        return;

    spectre_free_string( &operation->resultParam );
    operation->resultParam = spectre_strdup( args->resultParam );
}

void cli_algorithmVersion(Arguments *args, Operation *operation) {

    if (!args->algorithmVersion)
        return;
    if (!operation->site)
        abort();

    unsigned long algorithmVersion = strtoul( args->algorithmVersion, NULL, 10 );
    if (algorithmVersion < SpectreAlgorithmFirst || algorithmVersion > SpectreAlgorithmLast) {
        ftl( "Invalid algorithm version: %s", args->algorithmVersion );
        cli_free( args, operation );
        exit( EX_USAGE );
    }
    operation->site->algorithm = (SpectreAlgorithm)algorithmVersion;
}

void cli_fileRedacted(Arguments *args, Operation *operation) {

    if (args->fileRedacted)
        operation->user->redacted = spectre_get_bool( args->fileRedacted );

    else if (!operation->user->redacted)
        wrn( "User configuration file is not redacted.  Use -R 1 to change this." );
}

void cli_spectre(Arguments *args, Operation *operation) {

    if (!operation->site)
        abort();

    if (spectre_verbosity >= SpectreLogLevelInfo)
        fprintf( stderr, "%s's %s for %s:\n[ %s ]: ",
                operation->user->userName, operation->resultPurpose, operation->site->siteName, operation->identicon );

    // Check user keyID.
    const SpectreUserKey *userKey = NULL;
    if (operation->user->userKeyProvider)
        userKey = operation->user->userKeyProvider( operation->user->algorithm, operation->user->userName );
    if (!userKey) {
        ftl( "Couldn't derive user key." );
        cli_free( args, operation );
        exit( EX_SOFTWARE );
    }
    if (!spectre_id_valid( &operation->user->keyID ))
        operation->user->keyID = userKey->keyID;
    else if (!spectre_id_equals( &userKey->keyID, &operation->user->keyID )) {
        ftl( "user key mismatch." );
        spectre_free( &userKey, sizeof( *userKey ) );
        cli_free( args, operation );
        exit( EX_SOFTWARE );
    }

    // Resolve user key for site.
    spectre_free( &userKey, sizeof( *userKey ) );
    if (operation->user->userKeyProvider)
        userKey = operation->user->userKeyProvider( operation->algorithm, operation->user->userName );
    if (!userKey) {
        ftl( "Couldn't derive user key." );
        cli_free( args, operation );
        exit( EX_SOFTWARE );
    }

    // Update state from resultParam if stateful.
    if (operation->resultType & SpectreResultClassStateful && operation->resultParam) {
        spectre_free_string( &operation->resultState );
        if (!(operation->resultState =
                spectre_site_state( userKey, operation->siteName,
                        operation->resultType, operation->resultParam,
                        operation->keyCounter, operation->keyPurpose, operation->keyContext ))) {
            ftl( "Couldn't encrypt result." );
            spectre_free( &userKey, sizeof( *userKey ) );
            cli_free( args, operation );
            exit( EX_SOFTWARE );
        }
        inf( "(state) %s => ", operation->resultState );

        switch (operation->keyPurpose) {
            case SpectreKeyPurposeAuthentication: {
                spectre_free_string( &operation->site->resultState );
                operation->site->resultState = spectre_strdup( operation->resultState );
                break;
            }
            case SpectreKeyPurposeIdentification: {
                if (strcmp( operation->siteName, operation->userName ) == OK) {
                    spectre_free_string( &operation->user->loginState );
                    operation->user->loginState = spectre_strdup( operation->resultState );
                } else {
                    spectre_free_string( &operation->site->loginState );
                    operation->site->loginState = spectre_strdup( operation->resultState );
                }
                break;
            }

            case SpectreKeyPurposeRecovery: {
                spectre_free_string( &operation->question->state );
                operation->question->state = spectre_strdup( operation->resultState );
                break;
            }
        }

        // resultParam is consumed.
        spectre_free_string( &operation->resultParam );
    }

    // resultParam defaults to state.
    if (!operation->resultParam && operation->resultState)
        operation->resultParam = spectre_strdup( operation->resultState );

    // Generate result.
    const char *result = spectre_site_result( userKey, operation->siteName,
            operation->resultType, operation->resultParam, operation->keyCounter, operation->keyPurpose, operation->keyContext );
    spectre_free( &userKey, sizeof( *userKey ) );
    if (!result) {
        ftl( "Couldn't generate result." );
        cli_free( args, operation );
        exit( EX_SOFTWARE );
    }
    fflush( NULL );
    fprintf( stdout, "%s", result );
    if (!operation->omitNewline)
        fprintf( stdout, "\n" );
    if (operation->site->url)
        inf( "See: %s", operation->site->url );
    spectre_free_string( &result );

    // Update usage metadata.
    operation->site->lastUsed = operation->user->lastUsed = time( NULL );
    operation->site->uses++;
}

void cli_save(Arguments *args, Operation *operation) {

    if (!operation->file || !operation->user)
        return;

    if (!operation->fileFormatFixed)
        operation->fileFormat = SpectreFormatDefault;

    size_t count = 0;
    const char **extensions = spectre_format_extensions( operation->fileFormat, &count );
    if (!extensions || !count)
        return;

    spectre_free_string( &operation->filePath );
    operation->filePath = spectre_path( operation->user->userName, extensions[0] );
    dbg( "Updating: %s (%s)", operation->filePath, spectre_format_name( operation->fileFormat ) );
    spectre_free( &extensions, count * sizeof( *extensions ) );

    FILE *userFile = NULL;
    if (!operation->filePath || !spectre_mkdirs( operation->filePath ) || !(userFile = fopen( operation->filePath, "w" ))) {
        wrn( "Couldn't create updated configuration file:\n  %s: %s", operation->filePath, strerror( errno ) );
        return;
    }

    const char *buf = spectre_marshal_write( operation->fileFormat, &operation->file, operation->user );
    if (!buf || operation->file->error.type != SpectreMarshalSuccess)
        wrn( "Couldn't encode updated configuration file:\n  %s: %s", operation->filePath, operation->file->error.message );

    else if (fwrite( buf, sizeof( char ), strlen( buf ), userFile ) != strlen( buf ))
        wrn( "Error while writing updated configuration file:\n  %s: %d", operation->filePath, ferror( userFile ) );

    spectre_free_string( &buf );
    fclose( userFile );
}

static Operation *__spectre_proxy_provider_current_operation = NULL;

static bool __spectre_proxy_provider_operation(const SpectreUserKey **currentKey, SpectreAlgorithm *currentAlgorithm,
        SpectreAlgorithm algorithm, const char *userName) {

    if (!currentKey)
        __spectre_proxy_provider_current_operation = NULL;
    if (!__spectre_proxy_provider_current_operation)
        return false;

    return spectre_update_user_key( currentKey, currentAlgorithm, algorithm, userName,
                                    __spectre_proxy_provider_current_operation->userSecret );
}

SpectreKeyProvider spectre_proxy_provider_set_operation(Operation *operation) {

    spectre_proxy_provider_unset();
    __spectre_proxy_provider_current_operation = operation;
    return spectre_proxy_provider_set( __spectre_proxy_provider_operation );
}
