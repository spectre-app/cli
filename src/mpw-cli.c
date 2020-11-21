//==============================================================================
// This file is part of Master Password.
// Copyright (c) 2011-2017, Maarten Billemont.
//
// Master Password is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Master Password is distributed in the hope that it will be useful,
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

#include "mpw-cli-util.h"
#include "mpw-algorithm.h"
#include "mpw-util.h"
#include "mpw-marshal.h"
#include "mpw-marshal-util.h"

/** Output the program's usage documentation. */
static void usage() {

    inf( ""
         "  Master Password v%s - CLI\n"
         "--------------------------------------------------------------------------------\n"
         "      https://masterpassword.app\n", stringify_def( MP_VERSION ) );
    inf( ""
         "\nUSAGE\n\n"
         "  mpw [-u|-U full-name] [-m fd] [-t pw-type] [-P value] [-c counter]\n"
         "      [-a version] [-p purpose] [-C context] [-f|F format] [-R 0|1]\n"
         "      [-v|-q]* [-h] [service-name]\n" );
    inf( ""
         "  -u full-name Specify the full name of the user.\n"
         "               -u checks the master password against the config,\n"
         "               -U allows updating to a new master password.\n"
         "               Defaults to %s in env or prompts.\n", MP_ENV_fullName );
    inf( ""
         "  -m fd        Read the master password of the user from a file descriptor.\n"
         "               Tip: don't send extra characters like newlines such as by using\n"
         "               echo in a pipe.  Consider printf instead.\n" );
    dbg( ""
         "  -M master-pw Specify the master password of the user.\n"
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
         "                   -p i        | The login name for the service.\n"
         "                   -t K        | The bit size of the key to generate (eg. 256).\n"
         "                   -t P        | The personal password to encrypt.\n" );
    inf( ""
         "  -c counter   The value of the counter.\n"
         "               Defaults to 1.\n" );
    inf( ""
         "  -a version   The algorithm version to use, %d - %d.\n"
         "               Defaults to env var %s or %d.\n",
            MPAlgorithmVersionFirst, MPAlgorithmVersionLast, MP_ENV_algorithm, MPAlgorithmVersionCurrent );
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
         "                   f, flat     | ~/.mpw.d/Full Name.%s\n"
         "                   j, json     | ~/.mpw.d/Full Name.%s\n",
            mpw_format_name( MPMarshalFormatDefault ), MP_ENV_format, mpw_format_name( MPMarshalFormatDefault ),
            mpw_format_extension( MPMarshalFormatFlat ), mpw_format_extension( MPMarshalFormatJSON ) );
    inf( ""
         "  -R redacted  Whether to save the file in redacted format or not.\n"
         "               Redaction omits or encrypts any secrets, making the file safe\n"
         "               for saving on or transmitting via untrusted media.\n"
         "               Defaults to 1, redacted.\n" );
    inf( ""
         "  -v           Increase output verbosity (can be repeated).\n"
         "  -q           Decrease output verbosity (can be repeated).\n" );
    inf( ""
         "  -h           Show this help output instead of performing any operation.\n" );
    inf( ""
         "  service-name Name of the service for which to generate a token.\n" );
    inf( ""
         "\nENVIRONMENT\n\n"
         "  %-12s The full name of the user (see -u).\n"
         "  %-12s The default algorithm version (see -a).\n"
         "  %-12s The default file format (see -f).\n"
         "  %-12s The askpass program to use for prompting the user.\n",
            MP_ENV_fullName, MP_ENV_algorithm, MP_ENV_format, MP_ENV_askpass );
    exit( EX_OK );
}

// Internal state.

typedef struct {
    const char *fullName;
    const char *masterPasswordFD;
    const char *masterPassword;
    const char *serviceName;
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
    bool allowPasswordUpdate;
    bool fileFormatFixed;
    MPMarshalFormat fileFormat;
    const char *filePath;
    const char *fullName;
    const char *masterPassword;
    const char *identicon;
    const char *serviceName;
    MPResultType resultType;
    const char *resultState;
    const char *resultParam;
    const char *resultPurpose;
    MPCounterValue keyCounter;
    MPKeyPurpose keyPurpose;
    const char *keyContext;
    MPAlgorithmVersion algorithm;
    MPMarshalledFile *file;
    MPMarshalledUser *user;
    MPMarshalledService *service;
    MPMarshalledQuestion *question;
} Operation;

// Processing steps.

void cli_free(Arguments *args, Operation *operation);
void cli_args(Arguments *args, Operation *operation, const int argc, char *const argv[]);
void cli_fullName(Arguments *args, Operation *operation);
void cli_masterPassword(Arguments *args, Operation *operation);
void cli_serviceName(Arguments *args, Operation *operation);
void cli_fileFormat(Arguments *args, Operation *operation);
void cli_keyCounter(Arguments *args, Operation *operation);
void cli_keyPurpose(Arguments *args, Operation *operation);
void cli_keyContext(Arguments *args, Operation *operation);
void cli_user(Arguments *args, Operation *operation);
void cli_service(Arguments *args, Operation *operation);
void cli_question(Arguments *args, Operation *operation);
void cli_resultType(Arguments *args, Operation *operation);
void cli_resultState(Arguments *args, Operation *operation);
void cli_resultParam(Arguments *args, Operation *operation);
void cli_algorithmVersion(Arguments *args, Operation *operation);
void cli_fileRedacted(Arguments *args, Operation *operation);
void cli_mpw(Arguments *args, Operation *operation);
void cli_save(Arguments *args, Operation *operation);

MPMasterKeyProvider cli_masterKeyProvider_op(Operation *operation);

/** ========================================================================
 *  MAIN                                                                     */
int main(const int argc, char *const argv[]) {

    // Application defaults.
    Arguments args = {
            .fullName = mpw_getenv( MP_ENV_fullName ),
            .algorithmVersion = mpw_getenv( MP_ENV_algorithm ),
            .fileFormat = mpw_getenv( MP_ENV_format ),
    };
    Operation operation = {
            .allowPasswordUpdate = false,
            .fileFormatFixed = false,
            .fileFormat = MPMarshalFormatDefault,
            .resultType = MPResultTypeDefaultResult,
            .keyCounter = MPCounterValueDefault,
            .keyPurpose = MPKeyPurposeAuthentication,
    };

    // Read the command-line options.
    cli_args( &args, &operation, argc, argv );

    // Determine the operation parameters not sourced from the user's file.
    cli_fullName( &args, &operation );
    cli_masterPassword( &args, &operation );
    cli_serviceName( &args, &operation );
    cli_fileFormat( &args, &operation );
    cli_keyPurpose( &args, &operation );
    cli_keyContext( &args, &operation );

    // Load the operation parameters present in the user's file.
    cli_user( &args, &operation );
    cli_service( &args, &operation );
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
        dbg( "fullName         : %s", operation.user->fullName );
        dbg( "identicon        : %s", operation.identicon );
        dbg( "fileFormat       : %s%s", mpw_format_name( operation.fileFormat ), operation.fileFormatFixed? " (fixed)": "" );
        dbg( "filePath         : %s", operation.filePath );
    }
    if (operation.service) {
        dbg( "serviceName      : %s", operation.serviceName );
        dbg( "resultType       : %s (%u)", mpw_type_short_name( operation.resultType ), operation.resultType );
        dbg( "resultParam      : %s", operation.resultParam );
        dbg( "keyCounter       : %u", operation.keyCounter );
        dbg( "keyPurpose       : %s (%u)", mpw_purpose_name( operation.keyPurpose ), operation.keyPurpose );
        dbg( "keyContext       : %s", operation.keyContext );
        dbg( "algorithmVersion : %u", operation.algorithm );
    }
    dbg( "-----------------" );

    // Finally ready to perform the actual operation.
    cli_mpw( NULL, &operation );

    // Save changes and clean up.
    cli_save( NULL, &operation );
    cli_free( NULL, &operation );

    return EX_OK;
}

void cli_free(Arguments *args, Operation *operation) {

    if (args) {
        mpw_free_strings( &args->fullName, &args->masterPasswordFD, &args->masterPassword, &args->serviceName, NULL );
        mpw_free_strings( &args->resultType, &args->resultParam, &args->keyCounter, &args->algorithmVersion, NULL );
        mpw_free_strings( &args->keyPurpose, &args->keyContext, &args->fileFormat, &args->fileRedacted, NULL );
    }

    if (operation) {
        mpw_free_strings( &operation->fullName, &operation->masterPassword, &operation->serviceName, NULL );
        mpw_free_strings( &operation->keyContext, &operation->resultState, &operation->resultParam, NULL );
        mpw_free_strings( &operation->identicon, &operation->filePath, NULL );
        mpw_marshal_file_free( &operation->file );
        mpw_marshal_user_free( &operation->user );
        operation->service = NULL;
        operation->question = NULL;
        mpw_masterKeyProvider_free();
    }
}

void cli_args(Arguments *args, Operation *operation, const int argc, char *const argv[]) {

    for (int opt; (opt = getopt( argc, argv, "u:U:m:M:t:P:c:a:p:C:f:F:R:vqh" )) != EOF;
         optarg? mpw_zero( optarg, strlen( optarg ) ): (void)0)
        switch (opt) {
            case 'u':
                args->fullName = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                operation->allowPasswordUpdate = false;
                break;
            case 'U':
                args->fullName = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                operation->allowPasswordUpdate = true;
                break;
            case 'm':
                args->masterPasswordFD = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                break;
            case 'M':
                // Passing your master password via the command-line is insecure.  Testing purposes only.
                args->masterPassword = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                break;
            case 't':
                args->resultType = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                break;
            case 'P':
                args->resultParam = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                break;
            case 'c':
                args->keyCounter = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                break;
            case 'a':
                args->algorithmVersion = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                break;
            case 'p':
                args->keyPurpose = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                break;
            case 'C':
                args->keyContext = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                break;
            case 'f':
                args->fileFormat = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                operation->fileFormatFixed = false;
                break;
            case 'F':
                args->fileFormat = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                operation->fileFormatFixed = true;
                break;
            case 'R':
                args->fileRedacted = optarg && strlen( optarg )? mpw_strdup( optarg ): NULL;
                break;
            case 'v':
                ++mpw_verbosity;
                break;
            case 'q':
                --mpw_verbosity;
                break;
            case 'h':
                usage();
                break;
            case '?':
                switch (optopt) {
                    case 'u':
                        ftl( "Missing full name to option: -%c", optopt );
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
        args->serviceName = mpw_strdup( argv[optind] );
}

void cli_fullName(Arguments *args, Operation *operation) {

    mpw_free_string( &operation->fullName );

    if (args->fullName)
        operation->fullName = mpw_strdup( args->fullName );

    if (!operation->fullName || !strlen( operation->fullName ))
        do {
            operation->fullName = mpw_getline( "Your full name:" );
        } while (operation->fullName && !strlen( operation->fullName ));

    if (!operation->fullName || !strlen( operation->fullName )) {
        ftl( "Missing full name." );
        cli_free( args, operation );
        exit( EX_DATAERR );
    }
}

void cli_masterPassword(Arguments *args, Operation *operation) {

    mpw_free_string( &operation->masterPassword );

    if (args->masterPasswordFD) {
        operation->masterPassword = mpw_read_fd( (int)strtol( args->masterPasswordFD, NULL, 10 ) );
        if (!operation->masterPassword && errno)
            wrn( "Error reading master password from FD %s: %s", args->masterPasswordFD, strerror( errno ) );
    }

    if (args->masterPassword && !operation->masterPassword)
        operation->masterPassword = mpw_strdup( args->masterPassword );

    if (!operation->masterPassword || !strlen( operation->masterPassword ))
        do {
            operation->masterPassword = mpw_getpass( "Your master password: " );
        } while (operation->masterPassword && !strlen( operation->masterPassword ));

    if (!operation->masterPassword || !strlen( operation->masterPassword )) {
        ftl( "Missing master password." );
        cli_free( args, operation );
        exit( EX_DATAERR );
    }
}

void cli_serviceName(Arguments *args, Operation *operation) {

    mpw_free_string( &operation->serviceName );

    if (args->serviceName)
        operation->serviceName = mpw_strdup( args->serviceName );
    if (!operation->serviceName)
        operation->serviceName = mpw_getline( "Service name:" );

    if (!operation->serviceName) {
        ftl( "Missing service name." );
        cli_free( args, operation );
        exit( EX_DATAERR );
    }
}

void cli_fileFormat(Arguments *args, Operation *operation) {

    if (!args->fileFormat)
        return;

    operation->fileFormat = mpw_format_named( args->fileFormat );
    if (ERR == (int)operation->fileFormat) {
        ftl( "Invalid file format: %s", args->fileFormat );
        cli_free( args, operation );
        exit( EX_DATAERR );
    }
}

void cli_keyPurpose(Arguments *args, Operation *operation) {

    if (!args->keyPurpose)
        return;

    operation->keyPurpose = mpw_purpose_named( args->keyPurpose );
    if (ERR == (int)operation->keyPurpose) {
        ftl( "Invalid purpose: %s", args->keyPurpose );
        cli_free( args, operation );
        exit( EX_DATAERR );
    }
}

void cli_keyContext(Arguments *args, Operation *operation) {

    if (!args->keyContext)
        return;

    operation->keyContext = mpw_strdup( args->keyContext );
}

static FILE *cli_user_open(const MPMarshalFormat format, Operation *operation) {

    FILE *userFile = NULL;
    size_t count = 0;
    const char **extensions = mpw_format_extensions( format, &count );
    for (int e = 0; !userFile && e < count; ++e) {
        mpw_free_string( &operation->filePath );
        operation->filePath = mpw_path( operation->fullName, extensions[e] );

        if (!operation->filePath || !(userFile = fopen( operation->filePath, "r" )))
            dbg( "Couldn't open configuration file:\n  %s: %s", operation->filePath, strerror( errno ) );
    }
    mpw_free( &extensions, count * sizeof( *extensions ) );

    return userFile;
}

void cli_user(Arguments *args, Operation *operation) {

    // Find the user's file from parameters.
    FILE *userFile = cli_user_open( operation->fileFormat, operation );
    if (!userFile && !operation->fileFormatFixed)
        for (MPMarshalFormat format = MPMarshalFormatLast; !userFile && format >= MPMarshalFormatFirst; --format)
            userFile = cli_user_open( format, operation );

    if (!userFile) {
        // If no user from the user's file, create a new one.
        mpw_free_string( &operation->filePath );
        mpw_marshal_file_free( &operation->file );
        mpw_marshal_user_free( &operation->user );
        operation->file = mpw_marshal_file( NULL, NULL, NULL );
        operation->user = mpw_marshal_user( operation->fullName, cli_masterKeyProvider_op( operation ), MPAlgorithmVersionCurrent );
    }

    else {
        // Load the user object from the user's file.
        const char *fileInputData = mpw_read_file( userFile );
        if (!fileInputData || ferror( userFile ))
            wrn( "Error while reading configuration file:\n  %s: %d", operation->filePath, ferror( userFile ) );
        fclose( userFile );

        // Parse file.
        mpw_marshal_file_free( &operation->file );
        mpw_marshal_user_free( &operation->user );
        operation->file = mpw_marshal_read( NULL, fileInputData );
        if (operation->file && operation->file->error.type == MPMarshalSuccess) {
            operation->user = mpw_marshal_auth( operation->file, cli_masterKeyProvider_op( operation ) );

            if (operation->file->error.type == MPMarshalErrorMasterPassword && operation->allowPasswordUpdate) {
                // Update master password in the user's file.
                while (operation->file->error.type == MPMarshalErrorMasterPassword) {
                    inf( "Given master password does not match configuration." );
                    inf( "To update the configuration with this new master password, first confirm the old master password." );

                    const char *importMasterPassword = NULL;
                    while (!importMasterPassword || !strlen( importMasterPassword )) {
                        mpw_free_string( &importMasterPassword );
                        importMasterPassword = mpw_getpass( "Old master password: " );
                    }

                    mpw_marshal_user_free( &operation->user );
                    operation->user = mpw_marshal_auth( operation->file, mpw_masterKeyProvider_str( importMasterPassword ) );
                    if (operation->file && operation->user)
                        operation->user->masterKeyProvider = cli_masterKeyProvider_op( operation );
                    mpw_free_string( &importMasterPassword );
                }
            }
        }
        mpw_free_string( &fileInputData );

        // Incorrect master password.
        if (operation->file->error.type == MPMarshalErrorMasterPassword) {
            ftl( "Incorrect master password according to configuration:\n  %s: %s", operation->filePath, operation->file->error.message );
            cli_free( args, operation );
            exit( EX_DATAERR );
        }

        // Any other parse error.
        if (!operation->file || !operation->user || operation->file->error.type != MPMarshalSuccess) {
            err( "Couldn't parse configuration file:\n  %s: %s", operation->filePath, operation->file->error.message );
            cli_free( args, operation );
            exit( EX_DATAERR );
        }
    }

    if (operation->masterPassword)
        operation->user->identicon = mpw_identicon( operation->user->fullName, operation->masterPassword );
    mpw_free_string( &operation->identicon );
    operation->identicon = mpw_identicon_render( operation->user->identicon );
}

void cli_service(Arguments *args, Operation *operation) {

    if (!operation->serviceName)
        abort();

    // Load the service object from the user's file.
    MPMarshalledUser *user = operation->user;
    for (size_t s = 0; !operation->service && s < user->services_count; ++s)
        if (strcmp( operation->serviceName, (&user->services[s])->serviceName ) == OK)
            operation->service = &user->services[s];

    // If no service from the user's file, create a new one.
    if (!operation->service)
        operation->service = mpw_marshal_service(
                user, operation->serviceName, user->defaultType, MPCounterValueDefault, user->algorithm );
}

void cli_question(Arguments *args, Operation *operation) {

    if (!operation->service)
        abort();

    // Load the question object from the user's file.
    switch (operation->keyPurpose) {
        case MPKeyPurposeAuthentication:
        case MPKeyPurposeIdentification:
            break;
        case MPKeyPurposeRecovery:
            for (size_t q = 0; !operation->question && q < operation->service->questions_count; ++q)
                if (operation->keyContext == (&operation->service->questions[q])->keyword ||
                    (!operation->keyContext && !strlen( (&operation->service->questions[q])->keyword )) ||
                    (!(&operation->service->questions[q])->keyword && !strlen( operation->keyContext )) ||
                    ((operation->keyContext && (&operation->service->questions[q])->keyword) &&
                     strcmp( (&operation->service->questions[q])->keyword, operation->keyContext ) == OK))
                    operation->question = &operation->service->questions[q];

            // If no question from the user's file, create a new one.
            if (!operation->question)
                operation->question = mpw_marshal_question( operation->service, operation->keyContext );
            break;
    }
}

void cli_resultType(Arguments *args, Operation *operation) {

    if (!operation->service)
        abort();

    switch (operation->keyPurpose) {
        case MPKeyPurposeAuthentication: {
            operation->resultPurpose = "service password";
            operation->resultType = operation->service->resultType;
            operation->algorithm = operation->service->algorithm;
            break;
        }
        case MPKeyPurposeIdentification: {
            operation->resultPurpose = "service login";
            operation->resultType = operation->service->loginType;
            operation->algorithm = operation->service->algorithm;
            break;
        }
        case MPKeyPurposeRecovery: {
            operation->resultPurpose = "service answer";
            operation->resultType = operation->question->type;
            operation->algorithm = operation->service->algorithm;
            break;
        }
    }

    if (!args->resultType)
        return;

    operation->resultType = mpw_type_named( args->resultType );
    if (ERR == (int)operation->resultType) {
        ftl( "Invalid type: %s", args->resultType );
        cli_free( args, operation );
        exit( EX_USAGE );
    }

    if (!(operation->resultType & MPServiceFeatureAlternative)) {
        switch (operation->keyPurpose) {
            case MPKeyPurposeAuthentication:
                operation->service->resultType = operation->resultType;
                break;
            case MPKeyPurposeIdentification:
                operation->service->loginType = operation->resultType;
                break;
            case MPKeyPurposeRecovery:
                operation->question->type = operation->resultType;
                break;
        }
    }
}

void cli_resultState(Arguments *args, Operation *operation) {

    if (!operation->service)
        abort();

    switch (operation->keyPurpose) {
        case MPKeyPurposeAuthentication: {
            operation->resultState = operation->service->resultState? mpw_strdup( operation->service->resultState ): NULL;
            operation->keyCounter = operation->service->counter;
            break;
        }
        case MPKeyPurposeIdentification: {
            if (operation->resultType != MPResultTypeNone) {
                operation->resultState = operation->service->loginState? mpw_strdup( operation->service->loginState ): NULL;
                operation->keyCounter = MPCounterValueInitial;
            }
            else {
                // Identification at service-level is none, fall back to user-level.
                operation->resultPurpose = "global login";
                mpw_free_string( &operation->serviceName );
                operation->serviceName = mpw_strdup( operation->user->fullName );
                operation->resultType = operation->user->loginType;
                operation->resultState = operation->user->loginState? mpw_strdup( operation->user->loginState ): NULL;
                operation->keyCounter = MPCounterValueInitial;
                operation->algorithm = operation->user->algorithm;
            }
            break;
        }
        case MPKeyPurposeRecovery: {
            operation->resultState = operation->question->state? mpw_strdup( operation->question->state ): NULL;
            operation->keyCounter = MPCounterValueInitial;
            mpw_free_string( &operation->keyContext );
            operation->keyContext = operation->question->keyword? mpw_strdup( operation->question->keyword ): NULL;
            break;
        }
    }
}

void cli_keyCounter(Arguments *args, Operation *operation) {

    if (!args->keyCounter)
        return;
    if (!operation->service)
        abort();

    long long int keyCounterInt = strtoll( args->keyCounter, NULL, 0 );
    if (keyCounterInt < MPCounterValueFirst || keyCounterInt > MPCounterValueLast) {
        ftl( "Invalid counter: %s", args->keyCounter );
        cli_free( args, operation );
        exit( EX_USAGE );
    }

    switch (operation->keyPurpose) {
        case MPKeyPurposeAuthentication:
            operation->keyCounter = operation->service->counter = (MPCounterValue)keyCounterInt;
            break;
        case MPKeyPurposeIdentification:
        case MPKeyPurposeRecovery:
            // NOTE: counter for login & question is not persisted.
            break;
    }
}

void cli_resultParam(Arguments *args, Operation *operation) {

    if (!args->resultParam)
        return;

    mpw_free_string( &operation->resultParam );
    operation->resultParam = mpw_strdup( args->resultParam );
}

void cli_algorithmVersion(Arguments *args, Operation *operation) {

    if (!args->algorithmVersion)
        return;
    if (!operation->service)
        abort();

    unsigned long algorithmVersion = strtoul( args->algorithmVersion, NULL, 10 );
    if (algorithmVersion < MPAlgorithmVersionFirst || algorithmVersion > MPAlgorithmVersionLast) {
        ftl( "Invalid algorithm version: %s", args->algorithmVersion );
        cli_free( args, operation );
        exit( EX_USAGE );
    }
    operation->service->algorithm = (MPAlgorithmVersion)algorithmVersion;
}

void cli_fileRedacted(Arguments *args, Operation *operation) {

    if (args->fileRedacted)
        operation->user->redacted = mpw_get_bool( args->fileRedacted );

    else if (!operation->user->redacted)
        wrn( "User configuration file is not redacted.  Use -R 1 to change this." );
}

void cli_mpw(Arguments *args, Operation *operation) {

    if (!operation->service)
        abort();

    if (mpw_verbosity >= MPLogLevelInfo)
        fprintf( stderr, "%s's %s for %s:\n[ %s ]: ",
                operation->user->fullName, operation->resultPurpose, operation->service->serviceName, operation->identicon );

    // Check user keyID.
    const MPMasterKey *masterKey = NULL;
    if (operation->user->masterKeyProvider)
        masterKey = operation->user->masterKeyProvider( operation->user->algorithm, operation->user->fullName );
    if (!masterKey) {
        ftl( "Couldn't derive master key." );
        cli_free( args, operation );
        exit( EX_SOFTWARE );
    }
    if (!mpw_id_valid( &operation->user->keyID ))
        operation->user->keyID = masterKey->keyID;
    else if (!mpw_id_equals( &masterKey->keyID, &operation->user->keyID )) {
        ftl( "Master key mismatch." );
        mpw_free( &masterKey, sizeof( *masterKey ) );
        cli_free( args, operation );
        exit( EX_SOFTWARE );
    }

    // Resolve master key for service.
    mpw_free( &masterKey, sizeof( *masterKey ) );
    if (operation->user->masterKeyProvider)
        masterKey = operation->user->masterKeyProvider( operation->algorithm, operation->user->fullName );
    if (!masterKey) {
        ftl( "Couldn't derive master key." );
        cli_free( args, operation );
        exit( EX_SOFTWARE );
    }

    // Update state from resultParam if stateful.
    if (operation->resultType & MPResultTypeClassStateful && operation->resultParam) {
        mpw_free_string( &operation->resultState );
        if (!(operation->resultState =
                mpw_service_state( masterKey, operation->serviceName,
                        operation->resultType, operation->resultParam,
                        operation->keyCounter, operation->keyPurpose, operation->keyContext ))) {
            ftl( "Couldn't encrypt result." );
            mpw_free( &masterKey, sizeof( *masterKey ) );
            cli_free( args, operation );
            exit( EX_SOFTWARE );
        }
        inf( "(state) %s => ", operation->resultState );

        switch (operation->keyPurpose) {
            case MPKeyPurposeAuthentication: {
                mpw_free_string( &operation->service->resultState );
                operation->service->resultState = mpw_strdup( operation->resultState );
                break;
            }
            case MPKeyPurposeIdentification: {
                if (strcmp( operation->serviceName, operation->fullName ) == OK) {
                    mpw_free_string( &operation->user->loginState );
                    operation->user->loginState = mpw_strdup( operation->resultState );
                } else {
                    mpw_free_string( &operation->service->loginState );
                    operation->service->loginState = mpw_strdup( operation->resultState );
                }
                break;
            }

            case MPKeyPurposeRecovery: {
                mpw_free_string( &operation->question->state );
                operation->question->state = mpw_strdup( operation->resultState );
                break;
            }
        }

        // resultParam is consumed.
        mpw_free_string( &operation->resultParam );
    }

    // resultParam defaults to state.
    if (!operation->resultParam && operation->resultState)
        operation->resultParam = mpw_strdup( operation->resultState );

    // Generate result.
    const char *result = mpw_service_result( masterKey, operation->serviceName,
            operation->resultType, operation->resultParam, operation->keyCounter, operation->keyPurpose, operation->keyContext );
    mpw_free( &masterKey, sizeof( *masterKey ) );
    if (!result) {
        ftl( "Couldn't generate result." );
        cli_free( args, operation );
        exit( EX_SOFTWARE );
    }
    fflush( NULL );
    fprintf( stdout, "%s\n", result );
    if (operation->service->url)
        inf( "See: %s", operation->service->url );
    mpw_free_string( &result );

    // Update usage metadata.
    operation->service->lastUsed = operation->user->lastUsed = time( NULL );
    operation->service->uses++;
}

void cli_save(Arguments *args, Operation *operation) {

    if (!operation->file || !operation->user)
        return;

    if (!operation->fileFormatFixed)
        operation->fileFormat = MPMarshalFormatDefault;

    size_t count = 0;
    const char **extensions = mpw_format_extensions( operation->fileFormat, &count );
    if (!extensions || !count)
        return;

    mpw_free_string( &operation->filePath );
    operation->filePath = mpw_path( operation->user->fullName, extensions[0] );
    dbg( "Updating: %s (%s)", operation->filePath, mpw_format_name( operation->fileFormat ) );
    mpw_free( &extensions, count * sizeof( *extensions ) );

    FILE *userFile = NULL;
    if (!operation->filePath || !mpw_mkdirs( operation->filePath ) || !(userFile = fopen( operation->filePath, "w" ))) {
        wrn( "Couldn't create updated configuration file:\n  %s: %s", operation->filePath, strerror( errno ) );
        return;
    }

    const char *buf = mpw_marshal_write( operation->fileFormat, &operation->file, operation->user );
    if (!buf || operation->file->error.type != MPMarshalSuccess)
        wrn( "Couldn't encode updated configuration file:\n  %s: %s", operation->filePath, operation->file->error.message );

    else if (fwrite( buf, sizeof( char ), strlen( buf ), userFile ) != strlen( buf ))
        wrn( "Error while writing updated configuration file:\n  %s: %d", operation->filePath, ferror( userFile ) );

    mpw_free_string( &buf );
    fclose( userFile );
}

static Operation *__cli_masterKeyProvider_currentOperation = NULL;

static bool __cli_masterKeyProvider_op(const MPMasterKey **currentKey, MPAlgorithmVersion *currentAlgorithm,
        MPAlgorithmVersion algorithm, const char *fullName) {

    if (!currentKey)
        __cli_masterKeyProvider_currentOperation = NULL;
    if (!__cli_masterKeyProvider_currentOperation)
        return false;
    if (!mpw_update_master_key( currentKey, currentAlgorithm, algorithm, fullName,
            __cli_masterKeyProvider_currentOperation->masterPassword ))
        return false;

    return true;
}

MPMasterKeyProvider cli_masterKeyProvider_op(Operation *operation) {

    mpw_masterKeyProvider_free();
    __cli_masterKeyProvider_currentOperation = operation;
    return mpw_masterKeyProvider_proxy( __cli_masterKeyProvider_op );
}
