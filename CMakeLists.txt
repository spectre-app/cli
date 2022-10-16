### CMAKE
project( spectre-cli C )
cmake_minimum_required( VERSION 3.0.2 )
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")


### CONFIGURATION
# Features.
option( USE_SODIUM              "Implement crypto functions with sodium (depends on libsodium)." ON )
option( USE_JSON                "Support JSON-based user configuration format (depends on libjson-c)." ON )
option( USE_COLOR               "Colorized identicon (depends on libncurses)." ON )
option( USE_XML                 "XML parsing (depends on libxml2)." ON )

option( BUILD_SPECTRE           "C CLI version of Spectre (needs: spectre_sodium, optional: spectre_color, spectre_json)." ON )
option( BUILD_SPECTRE_BENCH     "C CLI Spectre benchmark utility (needs: spectre_sodium)." OFF )
option( BUILD_SPECTRE_TESTS     "C Spectre algorithm test suite (needs: spectre_sodium, spectre_xml)." OFF )

# Default build flags.
set( CMAKE_BUILD_TYPE           Release )
set( CMAKE_C_FLAGS              "-O3" )

# Version.
find_package( Git )
if( GIT_FOUND )
    execute_process( COMMAND    "${GIT_EXECUTABLE}" describe --match *-cli* --long --dirty
                     OUTPUT_VARIABLE spectre_version OUTPUT_STRIP_TRAILING_WHITESPACE )
endif()
if( NOT spectre_version MATCHES "." )
    file( READ                  "VERSION" spectre_version )
    string( STRIP               "${spectre_version}" spectre_version )
endif()
if( spectre_version MATCHES "." )
    add_definitions(            "-DMP_VERSION=${spectre_version}" )
    message( STATUS             "Current spectre source version ${spectre_version}..." )
else()
    message( STATUS             "Current spectre source version unknown..." )
endif()


### DEPENDENCIES
function( use_spectre_sodium t r )
    if( USE_SODIUM )
        set( sodium_USE_STATIC_LIBS ON )
        find_package( sodium )
        if ( sodium_FOUND )
            target_link_libraries( "${t}" PRIVATE sodium )
            target_compile_definitions( "${t}" PRIVATE -DSPECTRE_SODIUM=1 )
            message( STATUS     "${t}: USE_SODIUM is enabled." )

        elseif( r STREQUAL "required" )
            message( FATAL_ERROR "${t}: USE_SODIUM was enabled but is missing libsodium.  Please install this library before continuing." )

        else()
            message( WARNING    "${t}: USE_SODIUM was enabled but is missing libsodium.  Will continue with USE_SODIUM disabled!" )

        endif()

    elseif( r STREQUAL "required" )
        message( FATAL_ERROR    "${t}: USE_SODIUM was required but is not enabled.  Please enable the option or remove this target." )

    else()
        message( STATUS         "${t}: USE_SODIUM is supported but not enabled." )

    endif()
endfunction()

function( use_spectre_color t )
    if( USE_COLOR )
        find_package( Curses )
        if ( CURSES_FOUND )
            target_include_directories( "${t}" PRIVATE ${CURSES_INCLUDE_DIRS} )
            target_link_libraries( "${t}" PRIVATE ${CURSES_LIBRARIES} )
            target_compile_definitions( "${t}" PRIVATE -DSPECTRE_COLOR=1 ${CURSES_CFLAGS} )
            message( STATUS     "${t}: USE_COLOR is enabled." )

        elseif( r STREQUAL "required" )
            message( FATAL_ERROR "${t}: USE_COLOR was enabled but is missing libcurses.  Please install this library before continuing." )

        else()
            message( WARNING    "${t}: USE_COLOR was enabled but is missing libcurses.  Will continue with USE_COLOR disabled!" )

        endif()

    elseif( r STREQUAL "required" )
        message( FATAL_ERROR    "${t}: USE_COLOR was required but is not enabled.  Please enable the option or remove this target." )

    else()
        message( STATUS         "${t}: USE_COLOR is supported but not enabled." )

    endif()
endfunction()

function( use_spectre_json t )
    if( USE_JSON )
        find_package( json-c )
        if ( json-c_FOUND )
            target_link_libraries( "${t}" PRIVATE json-c::json-c-static )
            target_compile_definitions( "${t}" PRIVATE -DSPECTRE_JSON=1 )
            message( STATUS     "${t}: USE_JSON is enabled." )

        elseif( r STREQUAL "required" )
            message( FATAL_ERROR "${t}: USE_JSON was enabled but is missing libjson-c.  Please install this library before continuing." )

        else()
            message( WARNING    "${t}: USE_JSON was enabled but is missing libjson-c.  Will continue with USE_JSON disabled!" )

        endif()

    elseif( r STREQUAL "required" )
        message( FATAL_ERROR    "${t}: USE_JSON was required but is not enabled.  Please enable the option or remove this target." )

    else()
        message( STATUS         "${t}: USE_JSON is supported but not enabled." )

    endif()
endfunction()

function( use_spectre_xml t r )
    find_package( LibXml2 )
    if( USE_XML )
        if ( LIBXML2_FOUND )
            target_link_libraries( "${t}" PRIVATE LibXml2::LibXml2 )
            target_compile_definitions( "${t}" PRIVATE -DSPECTRE_XML=1 )
            message( STATUS     "${t}: USE_XML is enabled." )

        elseif( r STREQUAL "required" )
            message( FATAL_ERROR "${t}: USE_XML was enabled but is missing libxml2.  Please install this library before continuing." )

        else()
            message( WARNING    "${t}: USE_XML was enabled but is missing libxml2.  Will continue with USE_XML disabled!" )

        endif()

    elseif( r STREQUAL "required" )
        message( FATAL_ERROR    "${t}: USE_XML was required but is not enabled.  Please enable the option or remove this target." )

    else()
        message( STATUS         "${t}: USE_XML is supported but not enabled." )

    endif()
endfunction()


### TARGET: SPECTRE
if( BUILD_SPECTRE )
    # target
    add_executable( spectre "api/c/aes.c" "api/c/spectre-algorithm.c"
                        "api/c/spectre-algorithm_v0.c" "api/c/spectre-algorithm_v1.c" "api/c/spectre-algorithm_v2.c" "api/c/spectre-algorithm_v3.c"
                        "api/c/spectre-types.c" "api/c/spectre-util.c" "api/c/spectre-marshal-util.c" "api/c/spectre-marshal.c"
                        "src/spectre-cli-util.c" "src/spectre-cli.c" )
    target_include_directories( spectre PUBLIC api/c src )
    install( TARGETS spectre RUNTIME DESTINATION bin )

    # dependencies
    use_spectre_sodium( spectre required )
    use_spectre_color( spectre optional )
    use_spectre_json( spectre optional )
endif()


### TARGET: SPECTRE-BENCH
if( BUILD_SPECTRE_BENCH )
    # target
    add_executable( spectre-bench "api/c/aes.c" "api/c/spectre-algorithm.c"
                              "api/c/spectre-algorithm_v0.c" "api/c/spectre-algorithm_v1.c" "api/c/spectre-algorithm_v2.c" "api/c/spectre-algorithm_v3.c"
                              "api/c/spectre-types.c" "api/c/spectre-util.c" "src/spectre-bench.c" )
    target_include_directories( spectre-bench PUBLIC api/c src )
    install( TARGETS spectre-bench RUNTIME DESTINATION bin )

    # dependencies
    use_spectre_sodium( spectre-bench required )
endif()


### TARGET: SPECTRE-TESTS
if( BUILD_SPECTRE_TESTS )
    # target
    add_executable( spectre-tests "api/c/aes.c" "api/c/spectre-algorithm.c"
                              "api/c/spectre-algorithm_v0.c" "api/c/spectre-algorithm_v1.c" "api/c/spectre-algorithm_v2.c" "api/c/spectre-algorithm_v3.c"
                              "api/c/spectre-types.c" "api/c/spectre-util.c" "src/spectre-tests-util.c" "src/spectre-tests.c" )
    target_include_directories( spectre-tests PUBLIC api/c src )
    install( TARGETS spectre-tests RUNTIME DESTINATION bin )

    # dependencies
    use_spectre_sodium( spectre-tests required )
    use_spectre_xml( spectre-tests required )
endif()
