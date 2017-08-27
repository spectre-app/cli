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

#include <string.h>

#include "mpw-util.h"

#define MP_N                32768LU
#define MP_r                8U
#define MP_p                2U

// Inherited functions.
MPMasterKey mpw_masterKey_v0(
        const char *fullName, const char *masterPassword);
MPSiteKey mpw_siteKey_v0(
        MPMasterKey masterKey, const char *siteName, const MPCounterValue siteCounter,
        const MPKeyPurpose keyPurpose, const char *keyContext);
const char *mpw_sitePasswordFromCrypt_v0(
        MPMasterKey masterKey, MPSiteKey siteKey, const MPResultType resultType, const char *cipherText);
const char *mpw_sitePasswordFromDerive_v0(
        MPMasterKey masterKey, MPSiteKey siteKey, const MPResultType resultType, const char *resultParam);
const char *mpw_siteState_v0(
        MPMasterKey masterKey, MPSiteKey siteKey, const MPResultType resultType, const char *state);

// Algorithm version overrides.
static MPMasterKey mpw_masterKey_v1(
        const char *fullName, const char *masterPassword) {

    return mpw_masterKey_v0( fullName, masterPassword );
}

static MPSiteKey mpw_siteKey_v1(
        MPMasterKey masterKey, const char *siteName, const MPCounterValue siteCounter,
        const MPKeyPurpose keyPurpose, const char *keyContext) {

    return mpw_siteKey_v0( masterKey, siteName, siteCounter, keyPurpose, keyContext );
}

static const char *mpw_sitePasswordFromTemplate_v1(
        MPMasterKey masterKey, MPSiteKey siteKey, const MPResultType resultType, const char *resultParam) {

    // Determine the template.
    const char *template = mpw_templateForType( resultType, siteKey[0] );
    trc( "template: %u => %s\n", siteKey[0], template );
    if (!template)
        return NULL;
    if (strlen( template ) > MPSiteKeySize) {
        err( "Template too long for password seed: %zu\n", strlen( template ) );
        return NULL;
    }

    // Encode the password from the seed using the template.
    char *const sitePassword = calloc( strlen( template ) + 1, sizeof( char ) );
    for (size_t c = 0; c < strlen( template ); ++c) {
        sitePassword[c] = mpw_characterFromClass( template[c], siteKey[c + 1] );
        trc( "  - class: %c, index: %3u (0x%02hhX) => character: %c\n",
                template[c], siteKey[c + 1], siteKey[c + 1], sitePassword[c] );
    }
    trc( "  => password: %s\n", sitePassword );

    return sitePassword;
}

static const char *mpw_sitePasswordFromCrypt_v1(
        MPMasterKey masterKey, MPSiteKey siteKey, const MPResultType resultType, const char *cipherText) {

    return mpw_sitePasswordFromCrypt_v0( masterKey, siteKey, resultType, cipherText );
}

static const char *mpw_sitePasswordFromDerive_v1(
        MPMasterKey masterKey, MPSiteKey siteKey, const MPResultType resultType, const char *resultParam) {

    return mpw_sitePasswordFromDerive_v0( masterKey, siteKey, resultType, resultParam );
}

static const char *mpw_siteState_v1(
        MPMasterKey masterKey, MPSiteKey siteKey, const MPResultType resultType, const char *state) {

    return mpw_siteState_v0( masterKey, siteKey, resultType, state );
}
