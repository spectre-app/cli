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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "spectre-types.h"

#ifndef Spectre_VERSION
#define Spectre_VERSION ?
#endif

#define Spectre_ENV_userName     "SPECTRE_USERNAME"
#define Spectre_ENV_algorithm    "SPECTRE_ALGORITHM"
#define Spectre_ENV_format       "SPECTRE_FORMAT"
#define Spectre_ENV_askpass      "SPECTRE_ASKPASS"

/** Read the value of an environment variable.
  * @return A newly allocated string or NULL if the variable doesn't exist. */
const char *spectre_getenv(const char *variableName);

/** Use the askpass program to prompt the user.
  * @return A newly allocated string or NULL if askpass is not enabled or could not be executed. */
const char *spectre_askpass(const char *prompt);

/** Ask the user a question.
  * @return A newly allocated string or NULL if an error occurred trying to read from the user. */
const char *spectre_getline(const char *prompt);

/** Ask the user for a password.
  * @return A newly allocated string or NULL if an error occurred trying to read from the user. */
const char *spectre_getpass(const char *prompt);

/** Get the absolute path to the spectre configuration file with the given prefix name and file extension.
  * Resolves the file <prefix.extension> as located in the <.spectre.d> directory inside the user's home directory
  * or current directory if it couldn't be resolved.
  * @return A newly allocated string or NULL if the prefix or extension is missing or the path could not be allocated. */
const char *spectre_path(const char *prefix, const char *extension);

/** mkdir all the directories up to the directory of the given file path.
  * @return true if the file's path exists. */
bool spectre_mkdirs(const char *filePath);

/** Read until EOF from the given file descriptor.
  * @return A newly allocated string or NULL if the an IO error occurred or the read buffer couldn't be allocated. */
const char *spectre_read_fd(int fd);

/** Read the file contents of a given file.
  * @return A newly allocated string or NULL if the file is missing, an IO error occurred or the read buffer couldn't be allocated. */
const char *spectre_read_file(FILE *file);

/** Encode a visual fingerprint for a user.
  * @return A newly allocated string or NULL if the identicon couldn't be allocated. */
const char *spectre_identicon_render(SpectreIdenticon identicon);
