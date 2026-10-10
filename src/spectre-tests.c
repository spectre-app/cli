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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>

#include "spectre-algorithm.h"
#include "spectre-util.h"
#include "spectre-marshal.h"

#include "spectre-tests-util.h"

/** Output the program's usage documentation. */
static void usage() {

    inf( ""
            "  Spectre v%s - Tests\n"
            "--------------------------------------------------------------------------------\n"
            "      https://spectre.app\n", stringify_def( Spectre_VERSION ) );
    inf( ""
            "\nUSAGE\n\n"
            "  spectre-tests [-v|-q]* [-h] [test-name ...]\n" );
    inf( ""
            "  -v           Increase output verbosity (can be repeated).\n"
            "  -q           Decrease output verbosity (can be repeated).\n" );
    inf( ""
            "  -h           Show this help output instead of performing any operation.\n" );
    inf( ""
            "  test-name    Only run tests whose identifier starts with one of the these.\n" );
    exit( EX_OK );
}

static const char *spectre_test_error_name(SpectreMarshalErrorType type) {

    switch (type) {
        case SpectreMarshalSuccess:
            return "Success";
        case SpectreMarshalErrorStructure:
            return "Structure";
        case SpectreMarshalErrorFormat:
            return "Format";
        case SpectreMarshalErrorMissing:
            return "Missing";
        case SpectreMarshalErrorUserSecret:
            return "UserSecret";
        case SpectreMarshalErrorIllegal:
            return "Illegal";
        case SpectreMarshalErrorInternal:
            return "Internal";
    }

    return "Unknown";
}

int main(int argc, char *const argv[]) {

    for (int opt; (opt = getopt( argc, argv, "vqh" )) != EOF;
         optarg? spectre_zero( optarg, strlen( optarg ) ): (void)0)
        switch (opt) {
            case 'v':
                ++spectre_verbosity;
                break;
            case 'q':
                --spectre_verbosity;
                break;
            case 'h':
                usage();
                break;
            case '?':
                err( "Unknown option: -%c", optopt );
                exit( EX_USAGE );
            default:
                err( "Unexpected option: %c", opt );
                exit( EX_USAGE );
        }

    int failedTests = 0;

    xmlDocPtr testsDoc = xmlParseFile( "spectre_tests.xml" );
    xmlNodePtr tests = xmlDocGetRootElement( testsDoc );
    if (!tests) {
        ftl( "Couldn't find test case: spectre_tests.xml" );
        abort();
    }

    for (xmlNodePtr testCase = tests->children; testCase; testCase = testCase->next) {
        if (testCase->type != XML_ELEMENT_NODE || xmlStrcmp( testCase->name, BAD_CAST "case" ) != 0)
            continue;

        // Read in the test case.
        xmlChar *id = spectre_xmlTestCaseString( testCase, "id" );
        SpectreAlgorithm algorithm = (SpectreAlgorithm)spectre_xmlTestCaseInteger( testCase, "algorithm" );
        xmlChar *userName = spectre_xmlTestCaseString( testCase, "userName" );
        xmlChar *userSecret = spectre_xmlTestCaseString( testCase, "userSecret" );
        xmlChar *keyIDString = spectre_xmlTestCaseString( testCase, "keyID" );
        xmlChar *siteName = spectre_xmlTestCaseString( testCase, "siteName" );
        SpectreCounter keyCounter = (SpectreCounter)spectre_xmlTestCaseInteger( testCase, "keyCounter" );
        xmlChar *resultTypeString = spectre_xmlTestCaseString( testCase, "resultType" );
        xmlChar *resultParam = spectre_xmlTestCaseString( testCase, "resultParam" );
        xmlChar *keyPurposeString = spectre_xmlTestCaseString( testCase, "keyPurpose" );
        xmlChar *keyContext = spectre_xmlTestCaseString( testCase, "keyContext" );
        xmlChar *result = spectre_xmlTestCaseString( testCase, "result" );
        xmlChar *formatString = spectre_xmlTestCaseString( testCase, "format" );
        xmlChar *input = spectre_xmlTestCaseString( testCase, "input" );
        xmlChar *errorString = spectre_xmlTestCaseString( testCase, "error" );

        SpectreKeyID keyID = spectre_id_str( (char *)keyIDString );
        SpectreResultType resultType = spectre_type_named( (char *)resultTypeString );
        SpectreKeyPurpose keyPurpose = spectre_purpose_named( (char *)keyPurposeString );
        SpectreFormat format = spectre_format_named( (char *)formatString );
        const char *error = xmlStrlen( errorString )? (char *)errorString: spectre_test_error_name( SpectreMarshalSuccess );

        SpectreMarshalledUser *user = NULL, *readUser = NULL;
        SpectreMarshalledFile *file = NULL, *readFile = NULL;
        const SpectreUserKey *userKey = NULL;
        const char *document = NULL, *testResult = NULL;

        // Run the test case.
        do {
            if (optind < argc) {
                bool selected = false;
                for (int a = optind; !selected && a < argc; ++a)
                    if (strstr( (char *)id, argv[a] ) == (char *)id)
                        selected = true;
                if (!selected)
                    break;
            }

            fprintf( stdout, "test case %s... ", id );
            fflush( stdout );

            if (!result) {
                fprintf( stdout, "abstract.\n" );
                break;
            }

            SpectreKeyProvider provider = spectre_proxy_provider_set_secret( (char *)userSecret );
            if (format != SpectreFormatNone || xmlStrlen( input )) {
                if (xmlStrlen( input ))
                    document = spectre_strdup( (char *)input );

                else {
                    // A stateful result carries its state in the case's resultParam; a templated one derives it.
                    const char *state = resultType & SpectreResultClassStateful? (char *)resultParam: NULL;

                    user = spectre_marshal_user( (char *)userName, provider, algorithm );
                    SpectreMarshalledSite *site = user? spectre_marshal_site(
                            user, (char *)siteName, resultType, keyCounter, algorithm ): NULL;
                    if (!site) {
                        fprintf( stdout, "FAILED!  (marshal: couldn't load the case into a user)\n" );
                        ++failedTests;
                        break;
                    }

                    user->keyID = keyID;
                    switch (keyPurpose) {
                        case SpectreKeyPurposeAuthentication:
                            site->resultState = spectre_strdup( state );
                            break;

                        case SpectreKeyPurposeIdentification:
                            site->loginType = resultType;
                            site->loginState = spectre_strdup( state );
                            break;

                        case SpectreKeyPurposeRecovery: {
                            SpectreMarshalledQuestion *question = spectre_marshal_question( site, (char *)keyContext );
                            if (question) {
                                question->type = resultType;
                                question->state = spectre_strdup( state );
                            }
                            break;
                        }
                    }

                    document = spectre_marshal_write( format, &file, user );
                    if (!file || file->error.type != SpectreMarshalSuccess) {
                        fprintf( stdout, "FAILED!  (write: %s: %s)\n",
                                spectre_test_error_name( file? file->error.type: SpectreMarshalErrorInternal ),
                                file && file->error.message? file->error.message: "no message" );
                        ++failedTests;
                        break;
                    }
                    if (!document || !strlen( document )) {
                        fprintf( stdout, "FAILED!  (write: produced an empty document)\n" );
                        ++failedTests;
                        break;
                    }
                }

                if (!(readFile = spectre_marshal_read( NULL, document ))) {
                    fprintf( stdout, "FAILED!  (read: couldn't allocate a file)\n" );
                    ++failedTests;
                    break;
                }
                if (readFile->error.type == SpectreMarshalSuccess)
                    readUser = spectre_marshal_auth( readFile, provider );
                if (strcmp( spectre_test_error_name( readFile->error.type ), error ) != OK) {
                    fprintf( stdout, "FAILED!  (error: got %s (%s) != expected %s)\n",
                            spectre_test_error_name( readFile->error.type ),
                            readFile->error.message? readFile->error.message: "no message", error );
                    ++failedTests;
                    break;
                }
                if (readFile->error.type != SpectreMarshalSuccess) {
                    // The case expected the document to be rejected, and it was: nothing left to derive.
                    fprintf( stdout, "pass.\n" );
                    break;
                }
                if (!readUser) {
                    fprintf( stdout, "FAILED!  (auth: succeeded without producing a user)\n" );
                    ++failedTests;
                    break;
                }
            }

            if (!(userKey = provider(
                    readUser? readUser->algorithm: algorithm,
                    readUser? readUser->userName: (char *)userName ))) {
                fprintf( stdout, "FAILED!  (userKey: couldn't derive user key)\n" );
                ++failedTests;
                break;
            }
            if (!spectre_id_equals( &keyID, &userKey->keyID )) {
                fprintf( stdout, "FAILED!  (keyID: got %s != expected %s)\n", userKey->keyID.hex, keyID.hex );
                ++failedTests;
                break;
            }

            if (!readUser)
                testResult = spectre_site_result( userKey, (char *)siteName, resultType, (char *)resultParam,
                        keyCounter, keyPurpose, (char *)keyContext );

            else {
                SpectreMarshalledSite *site = NULL;
                for (size_t s = 0; !site && s < readUser->sites_count; ++s)
                    if (readUser->sites[s].siteName && strcmp( readUser->sites[s].siteName, (char *)siteName ) == OK)
                        site = &readUser->sites[s];

                if (!site) {
                    fprintf( stdout, "FAILED!  (sites: the recovered user has no site %s)\n", siteName );
                    ++failedTests;
                    break;
                }

                switch (keyPurpose) {
                    case SpectreKeyPurposeAuthentication:
                        testResult = spectre_site_result( userKey, site->siteName, site->resultType,
                                site->resultState, site->counter, SpectreKeyPurposeAuthentication, NULL );
                        break;

                    case SpectreKeyPurposeIdentification:
                        testResult = spectre_site_result( userKey, site->siteName, site->loginType,
                                site->loginState, SpectreCounterInitial, SpectreKeyPurposeIdentification, NULL );
                        break;

                    case SpectreKeyPurposeRecovery: {
                        SpectreMarshalledQuestion *question = NULL;
                        for (size_t q = 0; !question && q < site->questions_count; ++q)
                            if (strcmp( spectre_default( "", site->questions[q].keyword ),
                                    spectre_default( "", (char *)keyContext ) ) == OK)
                                question = &site->questions[q];

                        if (question)
                            testResult = spectre_site_result( userKey, site->siteName, question->type,
                                    question->state, SpectreCounterInitial, SpectreKeyPurposeRecovery,
                                    question->keyword );
                        break;
                    }
                }
            }

            if (xmlStrcmp( xmlStrlen( result )? result: NULL, BAD_CAST testResult ) != 0) {
                fprintf( stdout, "FAILED!  (result: got %s != expected %s)\n", spectre_default( "(none)", testResult ),
                        xmlStrlen( result )? (char *)result: "(none)" );
                ++failedTests;
                break;
            }

            fprintf( stdout, "pass.\n" );
        } while (false);

        // Free test case.
        spectre_free( &userKey, sizeof( *userKey ) );
        spectre_free_strings( &document, &testResult, NULL );
        spectre_marshal_free( &readUser );
        spectre_marshal_free( &readFile );
        spectre_marshal_free( &user );
        spectre_marshal_free( &file );
        xmlFree( id );
        xmlFree( userName );
        xmlFree( userSecret );
        xmlFree( keyIDString );
        xmlFree( siteName );
        xmlFree( resultTypeString );
        xmlFree( resultParam );
        xmlFree( keyPurposeString );
        xmlFree( keyContext );
        xmlFree( result );
        xmlFree( formatString );
        xmlFree( input );
        xmlFree( errorString );
    }
    xmlFreeDoc( testsDoc );

    return failedTests;
}
