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

#include "mpw-algorithm.h"
#include "mpw-algorithm_v0.c"
#include "mpw-algorithm_v1.c"
#include "mpw-algorithm_v2.c"
#include "mpw-algorithm_v3.c"

MPMasterKey mpw_masterKey(const char *fullName, const char *masterPassword, const MPAlgorithmVersion algorithmVersion) {

    trc( "-- mpw_masterKey (algorithm: %u)\n", algorithmVersion );
    trc( "fullName: %s\n", fullName );
    trc( "masterPassword.id: %s\n", mpw_id_buf( masterPassword, strlen( masterPassword ) ) );
    if (!fullName || !masterPassword)
        return NULL;

    switch (algorithmVersion) {
        case MPAlgorithmVersion0:
            return mpw_masterKey_v0( fullName, masterPassword );
        case MPAlgorithmVersion1:
            return mpw_masterKey_v1( fullName, masterPassword );
        case MPAlgorithmVersion2:
            return mpw_masterKey_v2( fullName, masterPassword );
        case MPAlgorithmVersion3:
            return mpw_masterKey_v3( fullName, masterPassword );
        default:
            err( "Unsupported version: %d\n", algorithmVersion );
            return NULL;
    }
}

MPSiteKey mpw_siteKey(
        MPMasterKey masterKey, const char *siteName, const MPCounterValue siteCounter,
        const MPKeyPurpose keyPurpose, const char *keyContext, const MPAlgorithmVersion algorithmVersion) {

    trc( "-- mpw_siteKey (algorithm: %u)\n", algorithmVersion );
    trc( "siteName: %s\n", siteName );
    trc( "siteCounter: %d\n", siteCounter );
    trc( "keyPurpose: %d (%s)\n", keyPurpose, mpw_nameForPurpose( keyPurpose ) );
    trc( "keyContext: %s\n", keyContext );
    if (!masterKey || !siteName)
        return NULL;

    switch (algorithmVersion) {
        case MPAlgorithmVersion0:
            return mpw_siteKey_v0( masterKey, siteName, siteCounter, keyPurpose, keyContext );
        case MPAlgorithmVersion1:
            return mpw_siteKey_v1( masterKey, siteName, siteCounter, keyPurpose, keyContext );
        case MPAlgorithmVersion2:
            return mpw_siteKey_v2( masterKey, siteName, siteCounter, keyPurpose, keyContext );
        case MPAlgorithmVersion3:
            return mpw_siteKey_v3( masterKey, siteName, siteCounter, keyPurpose, keyContext );
        default:
            err( "Unsupported version: %d\n", algorithmVersion );
            return NULL;
    }
}

const char *mpw_siteResult(
        MPMasterKey masterKey, const char *siteName, const MPCounterValue siteCounter,
        const MPKeyPurpose keyPurpose, const char *keyContext,
        const MPResultType resultType, const char *resultParam,
        const MPAlgorithmVersion algorithmVersion) {

    MPSiteKey siteKey = mpw_siteKey( masterKey, siteName, siteCounter, keyPurpose, keyContext, algorithmVersion );
    if (!siteKey)
        return NULL;

    trc( "-- mpw_siteResult (algorithm: %u)\n", algorithmVersion );
    trc( "resultType: %d (%s)\n", resultType, mpw_nameForType( resultType ) );
    trc( "resultParam: %s\n", resultParam );

    char *sitePassword = NULL;
    if (resultType & MPResultTypeClassTemplate) {
        switch (algorithmVersion) {
            case MPAlgorithmVersion0:
                return mpw_sitePasswordFromTemplate_v0( masterKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersion1:
                return mpw_sitePasswordFromTemplate_v1( masterKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersion2:
                return mpw_sitePasswordFromTemplate_v2( masterKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersion3:
                return mpw_sitePasswordFromTemplate_v3( masterKey, siteKey, resultType, resultParam );
            default:
                err( "Unsupported version: %d\n", algorithmVersion );
                return NULL;
        }
    }
    else if (resultType & MPResultTypeClassStateful) {
        switch (algorithmVersion) {
            case MPAlgorithmVersion0:
                return mpw_sitePasswordFromCrypt_v0( masterKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersion1:
                return mpw_sitePasswordFromCrypt_v1( masterKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersion2:
                return mpw_sitePasswordFromCrypt_v2( masterKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersion3:
                return mpw_sitePasswordFromCrypt_v3( masterKey, siteKey, resultType, resultParam );
            default:
                err( "Unsupported version: %d\n", algorithmVersion );
                return NULL;
        }
    }
    else if (resultType & MPResultTypeClassDerive) {
        switch (algorithmVersion) {
            case MPAlgorithmVersion0:
                return mpw_sitePasswordFromDerive_v0( masterKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersion1:
                return mpw_sitePasswordFromDerive_v1( masterKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersion2:
                return mpw_sitePasswordFromDerive_v2( masterKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersion3:
                return mpw_sitePasswordFromDerive_v3( masterKey, siteKey, resultType, resultParam );
            default:
                err( "Unsupported version: %d\n", algorithmVersion );
                return NULL;
        }
    }
    else {
        err( "Unsupported password type: %d\n", resultType );
    }

    return sitePassword;
}

const char *mpw_siteState(
        MPMasterKey masterKey, const char *siteName, const MPCounterValue siteCounter,
        const MPKeyPurpose keyPurpose, const char *keyContext,
        const MPResultType resultType, const char *state,
        const MPAlgorithmVersion algorithmVersion) {

    MPSiteKey siteKey = mpw_siteKey_v0( masterKey, siteName, siteCounter, keyPurpose, keyContext );
    if (!siteKey)
        return NULL;

    trc( "-- mpw_siteState (algorithm: %u)\n", algorithmVersion );
    trc( "resultType: %d (%s)\n", resultType, mpw_nameForType( resultType ) );
    trc( "state: %s\n", state );
    if (!masterKey || !state)
        return NULL;

    switch (algorithmVersion) {
        case MPAlgorithmVersion0:
            return mpw_siteState_v0( masterKey, siteKey, resultType, state );
        case MPAlgorithmVersion1:
            return mpw_siteState_v1( masterKey, siteKey, resultType, state );
        case MPAlgorithmVersion2:
            return mpw_siteState_v2( masterKey, siteKey, resultType, state );
        case MPAlgorithmVersion3:
            return mpw_siteState_v3( masterKey, siteKey, resultType, state );
        default:
            err( "Unsupported version: %d\n", algorithmVersion );
            return NULL;
    }
}
