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

//
//  spectre-bench.c
//  Spectre
//
//  Created by Maarten Billemont on 2014-12-20.
//  Copyright (c) 2014 Lyndir. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "bcrypt.c"

#include "spectre-algorithm.h"
#include "spectre-util.h"

#define Spectre_N                32768
#define Spectre_r                8
#define Spectre_p                2

static void spectre_time(struct timeval *time) {

    if (gettimeofday( time, NULL ) != OK)
        ftl( "Could not get time: %s", strerror( errno ) );
}

static const double spectre_show_speed(struct timeval startTime, const unsigned int iterations, const char *operation) {

    struct timeval endTime;
    spectre_time( &endTime );

    const time_t dsec = (endTime.tv_sec - startTime.tv_sec);
    const suseconds_t dusec = (endTime.tv_usec - startTime.tv_usec);
    const double elapsed = dsec + dusec / 1000000.;
    const double speed = iterations / elapsed;

    fprintf( stderr, " done.  " );
    fprintf( stdout, "%d %s iterations in %lus %luµs -> %.2f/s\n", iterations, operation, (unsigned long)dsec, (unsigned long)dusec, speed );

    return speed;
}

int main(int argc, char *const argv[]) {

    const char *userName = "Robert Lee Mitchel";
    const char *userSecret = "banana colored duckling";
    const char *siteName = "spectre.app";
    const SpectreResultType resultType = SpectreResultDefaultResult;
    const SpectreCounter keyCounter = SpectreCounterDefault;
    const SpectreKeyPurpose keyPurpose = SpectreKeyPurposeAuthentication;
    const char *keyContext = NULL;
    struct timeval startTime;
    unsigned int iterations;
    float percent;

    // Start HMAC-SHA-256
    // Similar to phase-two of spectre
    uint8_t *sitePasswordInfo = malloc( 128 );
    iterations = 4300000/* ~10s on dev machine */ * 2;
    const SpectreUserKey *userKey = spectre_user_key( userName, userSecret, SpectreAlgorithmCurrent );
    if (!userKey) {
        ftl( "Could not allocate user key: %s", strerror( errno ) );
        abort();
    }
    spectre_time( &startTime );
    for (int i = 1; i <= iterations; ++i) {
        uint8_t mac[32];
        spectre_hash_hmac_sha256( mac, userKey->bytes, sizeof( userKey->bytes ), sitePasswordInfo, 128 );

        if (modff( 100.f * i / iterations, &percent ) == 0)
            fprintf( stderr, "\rhmac-sha-256: iteration %d / %d (%.0f%%)..", i, iterations, percent );
    }
    const double hmacSha256Speed = spectre_show_speed( startTime, iterations, "hmac-sha-256" );
    free( (void *)userKey );

    // Start BCrypt
    // Similar to phase-one of spectre
    uint8_t bcrypt_rounds = 10;
    iterations = 170/* ~10s on dev machine */ * 2;
    spectre_time( &startTime );
    for (int i = 1; i <= iterations; ++i) {
        bcrypt( userSecret, bcrypt_gensalt( bcrypt_rounds ) );

        if (modff( 100.f * i / iterations, &percent ) == 0)
            fprintf( stderr, "\rbcrypt-%d: iteration %d / %d (%.0f%%)..", bcrypt_rounds, i, iterations, percent );
    }
    const double bcryptSpeed = spectre_show_speed( startTime, iterations, "bcrypt" );

    // Start SCrypt
    // Phase one of spectre
    uint8_t scrypt_rounds = 15;
    iterations = 2/* ~10s on dev machine */ * 2;
    spectre_time( &startTime );
    uint8_t *key = malloc(64);
    for (int i = 1; i <= iterations; ++i) {
        spectre_kdf_scrypt( key, 64, (uint8_t *)userName, strlen( userName ), (uint8_t *)userSecret, strlen( userSecret ), pow( 2, scrypt_rounds ), 8, 2 );

        if (modff( 100.f * i / iterations, &percent ) == 0)
            fprintf( stderr, "\rscrypt-%d: iteration %d / %d (%.0f%%)..", scrypt_rounds, i, iterations, percent );
    }
    free( key );
    const double scryptSpeed = spectre_show_speed( startTime, iterations, "scrypt" );

    // Start SPECTRE
    // Both phases of spectre
    iterations = 50; /* tuned to ~10s on dev machine */
    spectre_time( &startTime );
    for (int i = 1; i <= iterations; ++i) {
        userKey = spectre_user_key( userName, userSecret, SpectreAlgorithmCurrent );
        if (!userKey) {
            ftl( "Could not allocate user key: %s", strerror( errno ) );
            break;
        }

        free( (void *)spectre_site_result(
                userKey, siteName, resultType, NULL, keyCounter, keyPurpose, keyContext ) );
        free( (void *)userKey );

        if (modff( 100.f * i / iterations, &percent ) == 0)
            fprintf( stderr, "\rspectre: iteration %d / %d (%.0f%%)..", i, iterations, percent );
    }
    const double spectreSpeed = spectre_show_speed( startTime, iterations, "spectre" );

    // Summarize.
    fprintf( stdout, "\n== SUMMARY ==\nOn this machine,\n" );
    fprintf( stdout, " - 1 spectre      = %13.6f x hmac-sha-256.\n",                hmacSha256Speed / spectreSpeed  );
    fprintf( stdout, " - 1 spectre      = %13.6f x bcrypt-%d.\n",                   bcryptSpeed     / spectreSpeed, bcrypt_rounds );
    fprintf( stdout, " - 1 spectre      = %13.6f x scrypt-%d.\n",                   scryptSpeed     / spectreSpeed, scrypt_rounds );
    fprintf( stdout, " - 1 bcrypt-%-4d  = %13.6f x hmac-sha-256.\n", bcrypt_rounds, hmacSha256Speed / bcryptSpeed   );
    fprintf( stdout, " - 1 bcrypt-%-4d  = %13.6f x scrypt-%d.\n", bcrypt_rounds,    scryptSpeed     / bcryptSpeed,  scrypt_rounds );
    fprintf( stdout, " - 1 scrypt-%-4d  = %13.6f x hmac-sha-256.\n", scrypt_rounds, hmacSha256Speed / scryptSpeed   );

    return 0;
}
