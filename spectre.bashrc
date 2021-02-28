## Added by Spectre
source bashlib
spectre() {
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
    SPECTRE_USERNAME=${SPECTRE_USERNAME:-$(ask 'Your Full Name:')}

    # Start Spectre and copy the output.
    printf %s "$(SPECTRE_USERNAME=$SPECTRE_USERNAME command spectre "$@")" | _copy
}
