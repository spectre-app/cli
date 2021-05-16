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

#ifndef spectre_log_do
#define spectre_log_do(level, format, ...) ({ \
    fprintf( stderr, format "\n", ##__VA_ARGS__ ); \
    if (level == ftl_level) \
        abort(); \
})
#endif

#include "spectre-algorithm.h"
#include "spectre-util.h"

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
                ftl( "Unknown option: -%c", optopt );
                exit( EX_USAGE );
            default:
                ftl( "Unexpected option: %c", opt );
                exit( EX_USAGE );
        }

    int failedTests = 0;

    xmlNodePtr tests = xmlDocGetRootElement( xmlParseFile( "spectre_tests.xml" ) );
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
        SpectreKeyID keyID = spectre_id_str( (char *)spectre_xmlTestCaseString( testCase, "keyID" ) );
        xmlChar *siteName = spectre_xmlTestCaseString( testCase, "siteName" );
        SpectreCounter keyCounter = (SpectreCounter)spectre_xmlTestCaseInteger( testCase, "keyCounter" );
        xmlChar *resultTypeString = spectre_xmlTestCaseString( testCase, "resultType" );
        xmlChar *resultParam = spectre_xmlTestCaseString( testCase, "resultParam" );
        xmlChar *keyPurposeString = spectre_xmlTestCaseString( testCase, "keyPurpose" );
        xmlChar *keyContext = spectre_xmlTestCaseString( testCase, "keyContext" );
        xmlChar *result = spectre_xmlTestCaseString( testCase, "result" );

        SpectreResultType resultType = spectre_type_named( (char *)resultTypeString );
        SpectreKeyPurpose keyPurpose = spectre_purpose_named( (char *)keyPurposeString );

        // Run the test case.
        do {
            if (optind < argc) {
                bool selected = false;
                for (int a = optind; !selected && a <= argc; ++a)
                    if (strstr((char *)id, argv[optind]) == (char *)id)
                        selected = true;
                if (!selected)
                    break;
            }

            fprintf( stdout, "test case %s... ", id );
            if (!xmlStrlen( result )) {
                fprintf( stdout, "abstract.\n" );
                break;
            }

            // 1. calculate the user key.
            const SpectreUserKey *userKey = spectre_user_key(
                    (char *)userName, (char *)userSecret, algorithm );
            if (!userKey) {
                ftl( "Couldn't derive user key." );
                break;
            }

            // Check the user key.
            if (!spectre_id_equals( &keyID, &userKey->keyID )) {
                ++failedTests;
                fprintf( stdout, "FAILED!  (keyID: got %s != expected %s)\n", userKey->keyID.hex, keyID.hex );
                break;
            }

            // 2. calculate the site password.
            const char *testResult = spectre_site_result(
                    userKey, (char *)siteName, resultType, (char *)resultParam, keyCounter, keyPurpose, (char *)keyContext );
            spectre_free( &userKey, sizeof( *userKey ) );
            if (!testResult) {
                ftl( "Couldn't derive site password." );
                break;
            }

            // Check the site result.
            if (xmlStrcmp( result, BAD_CAST testResult ) != 0) {
                ++failedTests;
                fprintf( stdout, "FAILED!  (result: got %s != expected %s)\n", testResult, result );
                spectre_free_string( &testResult );
                break;
            }
            spectre_free_string( &testResult );

            fprintf( stdout, "pass.\n" );
        } while(false);

        // Free test case.
        xmlFree( id );
        xmlFree( userName );
        xmlFree( userSecret );
        xmlFree( siteName );
        xmlFree( resultTypeString );
        xmlFree( resultParam );
        xmlFree( keyPurposeString );
        xmlFree( keyContext );
        xmlFree( result );
    }

    return failedTests;
}
