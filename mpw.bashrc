## Added by Spectre
source bashlib
mpw() {
    _copy() {
        if hash pbcopy 2>/dev/null; then
            pbcopy
        elif hash xclip 2>/dev/null; then
            xclip -selection clip
        else
            cat; echo 2>/dev/null
            return
        fi
        echo >&2 "Copied!"
    }

    # Empty the clipboard
    :| _copy 2>/dev/null

    # Ask for the user's name and password if not yet known.
    MPW_USERNAME=${MPW_USERNAME:-$(ask 'Your Full Name:')}

    # Start Spectre and copy the output.
    printf %s "$(MPW_USERNAME=$MPW_USERNAME command mpw "$@")" | _copy
}
