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

#include "spectre-cli-util.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>
#include <sysexits.h>

#define SPECTRE_MAX_INPUT 60

#if SPECTRE_COLOR
#include <curses.h>
#include <term.h>
#endif

#include "spectre-util.h"

const char *spectre_getenv(const char *variableName) {

    char *envBuf = getenv( variableName );
    return envBuf? spectre_strdup( envBuf ): NULL;
}

const char *spectre_askpass(const char *prompt) {

    const char *askpass = spectre_getenv( Spectre_ENV_askpass );
    if (!askpass)
        return NULL;

    int pipes[2];
    if (pipe( pipes ) == ERR) {
        wrn( "Couldn't create pipes for askpass: %s", strerror( errno ) );
        return NULL;
    }

    pid_t pid = fork();
    if (pid == ERR) {
        wrn( "Couldn't fork for askpass:\n  %s: %s", askpass, strerror( errno ) );
        return NULL;
    }

    if (!pid) {
        // askpass fork
        close( pipes[0] );
        if (dup2( pipes[1], STDOUT_FILENO ) == ERR)
            ftl( "Couldn't connect pipe to process: %s", strerror( errno ) );

        else if (execlp( askpass, askpass, prompt, NULL ) == ERR)
            ftl( "Couldn't execute askpass:\n  %s: %s", askpass, strerror( errno ) );

        exit( EX_SOFTWARE );
    }

    close( pipes[1] );
    const char *answer = spectre_read_fd( pipes[0] );
    close( pipes[0] );
    int status;
    if (waitpid( pid, &status, 0 ) == ERR) {
        wrn( "Couldn't wait for askpass: %s", strerror( errno ) );
        spectre_free_string( &answer );
        return NULL;
    }

    if (!WIFEXITED( status ) || WEXITSTATUS( status ) != EXIT_SUCCESS || !answer || !strlen( answer )) {
        // askpass failed.
        spectre_free_string( &answer );
        return NULL;
    }

    // Remove trailing newline.
    if (answer[strlen( answer ) - 1] == '\n')
        spectre_replace_string( answer, spectre_strndup( answer, strlen( answer ) - 1 ) );
    return answer;
}

static const char *_spectre_getline(const char *prompt, bool silent) {

    // Get answer from askpass.
    const char *answer = spectre_askpass( prompt );
    if (answer)
        return answer;

#if SPECTRE_COLOR
    // Initialize a curses screen.
    SCREEN *screen = newterm( NULL, stderr, stdin );
    if (screen) {
        start_color();
        init_pair( 1, COLOR_WHITE, COLOR_BLUE );
        init_pair( 2, COLOR_BLACK, COLOR_WHITE );
        int rows, cols;
        getmaxyx( stdscr, rows, cols );

        // Display a dialog box.
        int width = max( prompt? (int)strlen( prompt ): 0, SPECTRE_MAX_INPUT ) + 6;
        char *version = "spectre v" stringify_def( Spectre_VERSION );
        mvprintw( rows - 1, (cols - (int)strlen( version )) / 2, "%s", version );
        attron( A_BOLD );
        color_set( 2, NULL );
        mvprintw( rows / 2 - 1, (cols - width) / 2, "%s%*s%s", "*", width - 2, "", "*" );
        mvprintw( rows / 2 - 1, (cols - (int)strlen( prompt )) / 2, "%s", prompt );
        color_set( 1, NULL );
        mvprintw( rows / 2 + 0, (cols - width) / 2, "%s%*s%s", "|", width - 2, "", "|" );
        mvprintw( rows / 2 + 1, (cols - width) / 2, "%s%*s%s", "|", width - 2, "", "|" );
        mvprintw( rows / 2 + 2, (cols - width) / 2, "%s%*s%s", "|", width - 2, "", "|" );

        // Read response.
        color_set( 2, NULL );
        attron( A_STANDOUT );
        int result;
        char str[SPECTRE_MAX_INPUT + 1];
        if (silent) {
            mvprintw( rows / 2 + 1, (cols - 5) / 2, "[ * ]" );
            refresh();

            noecho();
            result = mvgetnstr( rows / 2 + 1, (cols - 1) / 2, str, SPECTRE_MAX_INPUT );
            echo();
        }
        else {
            mvprintw( rows / 2 + 1, (cols - (SPECTRE_MAX_INPUT + 2)) / 2, "%*s", SPECTRE_MAX_INPUT + 2, "" );
            refresh();

            echo();
            result = mvgetnstr( rows / 2 + 1, (cols - SPECTRE_MAX_INPUT) / 2, str, SPECTRE_MAX_INPUT );
        }
        attrset( 0 );
        endwin();
        delscreen( screen );

        return result == ERR? NULL: spectre_strndup( str, SPECTRE_MAX_INPUT );
    }
#endif

    // Get password from terminal.
    fprintf( stderr, "%s ", prompt );

    size_t bufSize = 0;
    ssize_t lineSize = getline( (char **)&answer, &bufSize, stdin );
    if (lineSize <= 1) {
        spectre_free_string( &answer );
        return NULL;
    }

    // Remove trailing newline.
    spectre_replace_string( answer, spectre_strndup( answer, (size_t)lineSize - 1 ) );
    return answer;
}

const char *spectre_getline(const char *prompt) {

    return _spectre_getline( prompt, false );
}

const char *spectre_getpass(const char *prompt) {

    return _spectre_getline( prompt, true );
}

const char *spectre_path(const char *prefix, const char *extension) {

    if (!prefix || !extension)
        return NULL;

    // Compose filename.
    const char *path = spectre_str( "%s.%s", prefix, extension );
    if (!path)
        return NULL;

    // This is a filename, remove all potential directory separators.
    for (char *slash; (slash = strstr( path, "/" )); *slash = '_');

    // Resolve user's home directory.
    const char *homeDir = NULL;
    if ((homeDir = getenv( "HOME" )))
        homeDir = spectre_strdup( homeDir );
    if (!homeDir)
        if ((homeDir = getenv( "USERPROFILE" )))
            homeDir = spectre_strdup( homeDir );
    if (!homeDir) {
        const char *homeDrive = getenv( "HOMEDRIVE" ), *homePath = getenv( "HOMEPATH" );
        if (homeDrive && homePath)
            homeDir = spectre_str( "%s%s", homeDrive, homePath );
    }
    if (!homeDir) {
        struct passwd *passwd = getpwuid( getuid() );
        if (passwd)
            homeDir = spectre_strdup( passwd->pw_dir );
    }
    if (!homeDir)
        homeDir = getcwd( NULL, 0 );

    // Compose pathname.
    if (homeDir) {
        const char *homePath = spectre_str( "%s/.spectre.d/%s", homeDir, path );
        spectre_free_string( &homeDir );

        if (homePath) {
            spectre_free_string( &path );
            path = homePath;
        }
    }

    return path;
}

bool spectre_mkdirs(const char *filePath) {

    if (!filePath)
        return false;

    // Save the cwd and for absolute paths, start at the root.
    char *cwd = getcwd( NULL, 0 );
    if (*filePath == '/')
        if (chdir( "/" ) == ERR)
            return false;

    // The path to mkdir is the filePath without the last path component.
    char *pathEnd = strrchr( filePath, '/' );
    if (!pathEnd)
        return true;

    // Walk the path.
    bool success = true;
    char *path = (char *)spectre_strndup( filePath, (size_t)(pathEnd - filePath) );
    for (char *dirName = strtok( path, "/" ); success && dirName; dirName = strtok( NULL, "/" )) {
        if (!strlen( dirName ))
            continue;

        success &= (mkdir( dirName, 0700 ) != ERR || errno == EEXIST) && chdir( dirName ) != ERR;
    }
    free( path );

    if (chdir( cwd ) == ERR)
        wrn( "Could not restore cwd:\n  %s: %s", cwd, strerror( errno ) );
    free( cwd );

    return success;
}

const char *spectre_read_fd(int fd) {

    char *buf = NULL;
    size_t blockSize = 4096, bufSize = 0, bufOffset = 0;
    ssize_t readSize = 0;
    while ((spectre_realloc( &buf, &bufSize, char, bufSize / sizeof( char ) + blockSize )) &&
           ((readSize = read( fd, buf + bufOffset, blockSize )) > 0));
    if (readSize == ERR)
        spectre_free( &buf, bufSize );

    return buf;
}

const char *spectre_read_file(FILE *file) {

    if (!file)
        return NULL;

    char *buf = NULL;
    size_t blockSize = 4096, bufSize = 0, bufOffset = 0, readSize = 0;
    while ((spectre_realloc( &buf, &bufSize, char, bufSize / sizeof( char ) + blockSize )) &&
           (bufOffset += (readSize = fread( buf + bufOffset, 1, blockSize, file ))) &&
           (readSize == blockSize));
    if (ferror( file ))
        spectre_free( &buf, bufSize );

    return buf;
}

#if SPECTRE_COLOR
static char *str_tputs;
static int str_tputs_cursor;
static const int str_tputs_max = 256;

static bool spectre_setupterm() {

    if (!isatty( STDERR_FILENO ))
        return false;

    static bool termsetup;
    if (!termsetup) {
        int errret;
        if (!(termsetup = (setupterm( NULL, STDERR_FILENO, &errret ) == OK))) {
            wrn( "Terminal doesn't support color (setupterm errret %d).", errret );
            return false;
        }
    }

    return true;
}

static int spectre_tputc(int c) {

    if (++str_tputs_cursor < str_tputs_max) {
        str_tputs[str_tputs_cursor] = (char)c;
        return OK;
    }

    return ERR;
}

static const char *spectre_tputs(const char *str, int affcnt) {

    if (str_tputs)
        spectre_free( &str_tputs, str_tputs_max );
    str_tputs = calloc( str_tputs_max, sizeof( char ) );
    str_tputs_cursor = -1;

    const char *result = tputs( str, affcnt, spectre_tputc ) == ERR? NULL: spectre_strndup( str_tputs, str_tputs_max );
    if (str_tputs)
        spectre_free( &str_tputs, str_tputs_max );

    return result;
}

#endif

const char *spectre_identicon_render(SpectreIdenticon identicon) {

    const char *colorString = NULL, *resetString = NULL;
#if SPECTRE_COLOR
    if (spectre_setupterm()) {
        colorString = spectre_tputs( tparm( tgetstr( "AF", NULL ), identicon.color ), 1 );
        resetString = spectre_tputs( tgetstr( "me", NULL ), 1 );
    }
#endif

    const char *str = spectre_str( "%s%s%s%s%s%s",
            colorString? colorString: "",
            identicon.leftArm, identicon.body, identicon.rightArm, identicon.accessory,
            resetString? resetString: "" );
    spectre_free_strings( &colorString, &resetString, NULL );

    return str;
}
