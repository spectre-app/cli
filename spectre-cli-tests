#!/usr/bin/env bash
cd "${BASH_SOURCE%/*}"


# Tooling
errors=0
keep=${keep:-0}
spectre_expect() {
    local expect=$1; shift
    local args=( "$@" ) OPTIND=1 user= format= redacted=1 purpose=authentication context=
    while getopts :u:U:s:S:t:P:c:a:p:C:f:F:R:vqh arg; do
        case $arg in
            u)  user=$OPTARG ;;
            F)  format=$OPTARG ;;
            R)  redacted=$OPTARG ;;
            t)  type=$OPTARG ;;
            p)  purpose=$OPTARG ;;
            C)  context=$OPTARG ;;
            *)  ;;
        esac
    done
    shift "$((OPTIND-1))"
    local site=$1

    local file=
    if (( ! redacted )); then
        case $format in
            flat)   file=~/.spectre.d/"$user.mpsites" ;;
            json)   file=~/.spectre.d/"$user.mpjson" ;;
        esac
    fi
    [[ -e $file ]] && (( ! keep )) && rm "$file"

    local result=$(./spectre -q "${args[@]}") err=$?

    if (( err )); then
        printf '*'
        printf >&2 "Error (exit %d) spectre%s\n" "$err" "$(printf ' %q' "${args[@]}")"
        return $(( ++errors ))
    fi
    if [[ $result != $expect ]]; then
        printf '!'
        printf >&2 "Bad result (got: %s != expected: %s) spectre%s\n" "$result" "$expect" "$(printf ' %q' "${args[@]}")"
        return $(( ++errors ))
    fi

    local one key password
    if (( ! redacted )); then
        case $format in
            flat)
                while IFS=$'\t' read -r one key password; do
                    read key <<< "$key"
                    [[ $key = $site ]] || continue

                    case $purpose in
                        a*) result=$password ;;
                        i*) [[ ! $type || $type = no* ]] && break
                            read _ _ _ result <<< "$one" ;;
                        r*) break ;;
                    esac

                    if [[ $result != $expect ]]; then
                        printf '#'
                        printf >&2 "Bad mpsites (found: %s != expected: %s) %s (after spectre%s)\n" "$result" "$expect" "$file" "$(printf ' %q' "${args[@]}")"
                        return $(( ++errors ))
                    fi

                    break
                done < "$file"
            ;;
            json)
                if ! hash jq 2>/dev/null; then
                    printf >&2 "Error: jq not installed. Please install through your package manager or from https://stedolan.github.io/jq/\n"
                    exit 1
                fi

                case $purpose in
                    a*) result=$(jq -r ".sites.\"$site\".password") ;;
                    i*) [[ $type && $type != none ]] \
                            && result=$(jq -r ".sites.\"$site\".login_name") \
                            || result=$(jq -r ".user.login_name") ;;
                    r*) result=$(jq -r ".sites.\"$site\".questions.\"$context\".answer") ;;
                esac < "$file"

                if [[ $result != $expect ]]; then
                    printf '#'
                    printf >&2 "Bad mpjson (found: %s != expected: %s) %s (after spectre%s)\n" "$result" "$expect" "$file" "$(printf ' %q' "${args[@]}")"
                    return $(( ++errors ))
                fi
            ;;
        esac
    fi

    printf '.'
    [[ -e $file ]] && (( ! keep )) && rm "$file"
}


#   spectre_tests.xml
##  V3
printf "\nV%d, none: " 3
spectre_expect 'CefoTiciJuba7@'         -Fnone \
    -u 'test' -S 'test'                                                        'test'
spectre_expect 'Tina0#NotaMahu'         -Fnone \
    -u 'tesẗ' -S 'ẗest'                                                        'ẗesẗ'
spectre_expect 'Tina0#NotaMahu'         -Fnone \
    -u 'tesẗ' -S 'ẗest'                                         -C ''          'ẗesẗ'
spectre_expect 'Tina0#NotaMahu'         -Fnone \
    -u 'tesẗ' -S 'ẗest'                     -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Tina0#NotaMahu'         -Fnone \
    -u 'tesẗ' -S 'ẗest'               -a3   -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Tina0#NotaMahu'         -Fnone \
    -u 'tesẗ' -S 'ẗest'             -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Tina0#NotaMahu'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'KovxFipe5:Zatu'         -Fnone \
    -u '⛄'   -S 'ẗest' -tlong      -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'ModoLalhRapo6#'         -Fnone \
    -u 'tesẗ' -S '⛄'   -tlong      -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'CudmTecuPune7:'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c1 -a3 -p 'authentication' -C ''          '⛄'
spectre_expect 'mebkovidu'              -Fnone \
    -u 'tesẗ' -S 'ẗest'                     -p 'identification' -C ''          'ẗesẗ'
spectre_expect 'mebkovidu'              -Fnone \
    -u 'tesẗ' -S 'ẗest' -tnone      -c1 -a3 -p 'identification' -C ''          'ẗesẗ'
spectre_expect 'yubfalago'              -Fnone \
    -u 'tesẗ' -S 'ẗest' -tname      -c1 -a3 -p 'identification' -C ''          'ẗesẗ'
spectre_expect 'jip nodwoqude dizo'     -Fnone \
    -u 'tesẗ' -S 'ẗest'                     -p 'recovery'       -C ''          'ẗesẗ'
spectre_expect 'jip nodwoqude dizo'     -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a3 -p 'recovery'       -C ''          'ẗesẗ'
spectre_expect 'dok sorkicoyu ruya'     -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a3 -p 'recovery'       -C 'quesẗion'  'ẗesẗ'
spectre_expect 'j5TJ%G0WWwSMvYb)hr4)'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tmax       -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'TinRaz2?'               -Fnone \
    -u 'tesẗ' -S 'ẗest' -tmed       -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'jad0IQA3'               -Fnone \
    -u 'tesẗ' -S 'ẗest' -tbasic     -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Tin0'                   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tshort     -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect '1710'                   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tpin       -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'tinraziqu'              -Fnone \
    -u 'tesẗ' -S 'ẗest' -tname      -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'tinr ziq taghuye zuj'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a3 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'HidiLonoFopt9&'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c4294967295 -a3 -p 'authentication' -C '' 'ẗesẗ'

##  V2
printf "\nV%d, none: " 2
spectre_expect 'CefoTiciJuba7@'         -Fnone \
    -u 'test' -S 'test' -tlong      -c1 -a2 -p 'authentication' -C ''          'test'
spectre_expect "HuczFina3'Qatf"         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c1 -a2 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'SicrJuwaWaql0#'         -Fnone \
    -u '⛄'   -S 'ẗest' -tlong      -c1 -a2 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'LokaJayp1@Faba'         -Fnone \
    -u 'tesẗ' -S '⛄'   -tlong      -c1 -a2 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'DoqaHulu8:Funh'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c1 -a2 -p 'authentication' -C ''          '⛄'
spectre_expect 'yiyguxoxe'              -Fnone \
    -u 'tesẗ' -S 'ẗest' -tname      -c1 -a2 -p 'identification' -C ''          'ẗesẗ'
spectre_expect 'vu yelyo bat kujavmu'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a2 -p 'recovery'       -C ''          'ẗesẗ'
spectre_expect 'ka deqce xad vomacgi'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a2 -p 'recovery'       -C 'quesẗion'  'ẗesẗ'
spectre_expect 'wRF$LmB@umWGLWeVlB0-'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tmax       -c1 -a2 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'HucZuk0!'               -Fnone \
    -u 'tesẗ' -S 'ẗest' -tmed       -c1 -a2 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'wb59VoB5'               -Fnone \
    -u 'tesẗ' -S 'ẗest' -tbasic     -c1 -a2 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Huc9'                   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tshort     -c1 -a2 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect '2959'                   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tpin       -c1 -a2 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'huczukamo'              -Fnone \
    -u 'tesẗ' -S 'ẗest' -tname      -c1 -a2 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'huc finmokozi fota'     -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a2 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Mixa1~BulgNijo'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c4294967295 -a2 -p 'authentication' -C '' 'ẗesẗ'

##  V1
printf "\nV%d, none: " 1
spectre_expect 'CefoTiciJuba7@'         -Fnone \
    -u 'test' -S 'test' -tlong      -c1 -a1 -p 'authentication' -C ''          'test'
spectre_expect 'SuxiHoteCuwe3/'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c1 -a1 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'CupaTixu8:Hetu'         -Fnone \
    -u '⛄'   -S 'ẗest' -tlong      -c1 -a1 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'NaqmBanu9+Decs'         -Fnone \
    -u 'tesẗ' -S '⛄'   -tlong      -c1 -a1 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'XowaDokoGeyu2)'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c1 -a1 -p 'authentication' -C ''          '⛄'
spectre_expect 'makmabivo'              -Fnone \
    -u 'tesẗ' -S 'ẗest' -tname      -c1 -a1 -p 'identification' -C ''          'ẗesẗ'
spectre_expect 'je mutbo buf puhiywo'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a1 -p 'recovery'       -C ''          'ẗesẗ'
spectre_expect 'ne hapfa dax qamayqo'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a1 -p 'recovery'       -C 'quesẗion'  'ẗesẗ'
spectre_expect 'JlZo&eLhqgoxqtJ!NC5/'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tmax       -c1 -a1 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'SuxHot2*'               -Fnone \
    -u 'tesẗ' -S 'ẗest' -tmed       -c1 -a1 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Jly28Veh'               -Fnone \
    -u 'tesẗ' -S 'ẗest' -tbasic     -c1 -a1 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Sux2'                   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tshort     -c1 -a1 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect '4922'                   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tpin       -c1 -a1 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'suxhotito'              -Fnone \
    -u 'tesẗ' -S 'ẗest' -tname      -c1 -a1 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'su hotte pav calewxo'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a1 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Luxn2#JapiXopa'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c4294967295 -a1 -p 'authentication' -C '' 'ẗesẗ'

##  V0
printf "\nV%d, none: " 0
spectre_expect 'GeqoBigiFubh2!'         -Fnone \
    -u 'test' -S 'test' -tlong      -c1 -a0 -p 'authentication' -C ''          'test'
spectre_expect 'WumiZobxGuhe8]'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c1 -a0 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'KuhaXimj8@Zebu'         -Fnone \
    -u '⛄'   -S 'ẗest' -tlong      -c1 -a0 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'CajtFayv9_Pego'         -Fnone \
    -u 'tesẗ' -S '⛄'   -tlong      -c1 -a0 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'QohaPokgYevu2!'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c1 -a0 -p 'authentication' -C ''          '⛄'
spectre_expect 'takxabico'              -Fnone \
    -u 'tesẗ' -S 'ẗest' -tname      -c1 -a0 -p 'identification' -C ''          'ẗesẗ'
spectre_expect 'je tuxfo fut huzivlo'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a0 -p 'recovery'       -C ''          'ẗesẗ'
spectre_expect 'ye zahqa lam jatavmo'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a0 -p 'recovery'       -C 'quesẗion'  'ẗesẗ'
spectre_expect 'g4@)4SlA#)cJ#ib)vvH3'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tmax       -c1 -a0 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Wum7_Xix'               -Fnone \
    -u 'tesẗ' -S 'ẗest' -tmed       -c1 -a0 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'gAo78ARD'               -Fnone \
    -u 'tesẗ' -S 'ẗest' -tbasic     -c1 -a0 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Wum7'                   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tshort     -c1 -a0 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect '9427'                   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tpin       -c1 -a0 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'wumdoxixo'              -Fnone \
    -u 'tesẗ' -S 'ẗest' -tname      -c1 -a0 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'wu doxbe hac kaselqo'   -Fnone \
    -u 'tesẗ' -S 'ẗest' -tphrase    -c1 -a0 -p 'authentication' -C ''          'ẗesẗ'
spectre_expect 'Pumy7.JadjQoda'         -Fnone \
    -u 'tesẗ' -S 'ẗest' -tlong      -c4294967295 -a0 -p 'authentication' -C '' 'ẗesẗ'

##  V3
printf "\nV%d, flat: " 3
spectre_expect 'IfHuAUUpqpKZDZlNvz8$'   -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tmax    -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.max'
spectre_expect 'FamiJirk1)Zehc'         -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tlong   -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.long'
spectre_expect 'NofhMusw8+Cebo'         -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tlong   -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.⛄'
spectre_expect 'Necx1$LagaRizu'         -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest'          -c4294967295 -a3 -p 'authentication' -C '' 'ẗesẗ.c+a3pa'
spectre_expect 'Poq2)Tey'               -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tmed    -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.med'
spectre_expect 'Wr07Okx0'               -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tbasic  -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.basic'
spectre_expect 'Bug9'                   -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tshort  -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.short'
spectre_expect '3560'                   -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tpin    -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.pin'
spectre_expect 'jupxiqepi'              -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tname   -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.name'
spectre_expect 'vuh buxtukewo puhe'     -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tphrase -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.phrase'
spectre_expect 'Cq5$TfH#OHmPS9yREp7)'   -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tmax    -c1 -a3 -p 'identification' -C ''          'ẗesẗ.c1a3pi.max'
spectre_expect 'secgudiho'              -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tnone   -c1 -a3 -p 'identification' -C ''          'ẗesẗ.c1a3pi'
spectre_expect 'mophabiwe'              -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tname   -c1 -a3 -p 'identification' -C ''          'ẗesẗ.c1a3pi'
spectre_expect 'lA^ul!%9&TD%fj6icT1['   -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tmax    -c1 -a3 -p 'recovery'       -C ''          'ẗesẗ.c1a3pr.max'
spectre_expect 'mup wulbezaxa juca'     -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest'          -c1 -a3 -p 'recovery'       -C ''          'ẗesẗ.c1a3pr'
spectre_expect 'molg rux kaczuvi ror'   -Fflat -R0 \
    -u 'tesẗ.v3' -S 'ẗest'          -c1 -a3 -p 'recovery'       -C 'quesẗion'  'ẗesẗ.c1a3pr.quesẗion'

##  V2
printf "\nV%d, flat: " 2
spectre_expect 'i7@0M*DdP4DgD#jJIzyL'   -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tmax    -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.max'
spectre_expect 'Lifw5]DablSuga'         -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tlong   -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.long'
spectre_expect 'Leja5%RavoZapa'         -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tlong   -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.⛄'
spectre_expect 'NejnGazo8?Seqo'         -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest'          -c4294967295 -a2 -p 'authentication' -C '' 'ẗesẗ.c+a2pa'
spectre_expect 'XicSux2&'               -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tmed    -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.med'
spectre_expect 'uEY50hcZ'               -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tbasic  -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.basic'
spectre_expect 'Jif6'                   -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tshort  -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.short'
spectre_expect '4001'                   -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tpin    -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.pin'
spectre_expect 'rexmibace'              -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tname   -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.name'
spectre_expect 'cez fexlemozo yula'     -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tphrase -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.phrase'
spectre_expect 'T8+xi4NMd3HUGdV#GW*%'   -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tmax    -c1 -a2 -p 'identification' -C ''          'ẗesẗ.c1a2pi.max'
spectre_expect 'nidcepede'              -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tnone   -c1 -a2 -p 'identification' -C ''          'ẗesẗ.c1a2pi'
spectre_expect 'camfibeye'              -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tname   -c1 -a2 -p 'identification' -C ''          'ẗesẗ.c1a2pi'
spectre_expect 'YLcoWeBwyiBf2*irFq1.'   -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tmax    -c1 -a2 -p 'recovery'       -C ''          'ẗesẗ.c1a2pr.max'
spectre_expect 'ye vemcu keq xepewmi'   -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest'          -c1 -a2 -p 'recovery'       -C ''          'ẗesẗ.c1a2pr'
spectre_expect 'yi qazne tid najuvme'   -Fflat -R0 \
    -u 'tesẗ.v2' -S 'ẗest'          -c1 -a2 -p 'recovery'       -C 'quesẗion'  'ẗesẗ.c1a2pr.quesẗion'

##  V1
printf "\nV%d, flat: " 1
spectre_expect 'a3~AiGkHk)Pgjbb)mk6H'   -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tmax    -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.max'
spectre_expect 'Lojz6?VotaJall'         -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tlong   -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.long'
spectre_expect 'Yoqu7)NiziFito'         -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tlong   -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.⛄'
spectre_expect 'Foha4[TojmXanc'         -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest'          -c4294967295 -a1 -p 'authentication' -C '' 'ẗesẗ.c+a1pa'
spectre_expect 'Hiy3*Zag'               -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tmed    -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.med'
spectre_expect 'UJR7HpG0'               -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tbasic  -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.basic'
spectre_expect 'Cij7'                   -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tshort  -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.short'
spectre_expect '0020'                   -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tpin    -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.pin'
spectre_expect 'vadxovezu'              -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tname   -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.name'
spectre_expect 'sij jihloyenu kizi'     -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tphrase -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.phrase'
spectre_expect 'z2U9)(uQ78TXqtaus)8.'   -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tmax    -c1 -a1 -p 'identification' -C ''          'ẗesẗ.c1a1pi.max'
spectre_expect 'wexducuvi'              -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tnone   -c1 -a1 -p 'identification' -C ''          'ẗesẗ.c1a1pi'
spectre_expect 'qipberize'              -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tname   -c1 -a1 -p 'identification' -C ''          'ẗesẗ.c1a1pi'
spectre_expect 'QMciaKyi1&I*g%tHz99,'   -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tmax    -c1 -a1 -p 'recovery'       -C ''          'ẗesẗ.c1a1pr.max'
spectre_expect 'sok torxibute reza'     -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest'          -c1 -a1 -p 'recovery'       -C ''          'ẗesẗ.c1a1pr'
spectre_expect 'xacp qaw qutbece gan'   -Fflat -R0 \
    -u 'tesẗ.v1' -S 'ẗest'          -c1 -a1 -p 'recovery'       -C 'quesẗion'  'ẗesẗ.c1a1pr.quesẗion'

##  V0
printf "\nV%d, flat: " 0
spectre_expect 'b5@ww@Jmb4cAioRbivb)'   -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tmax    -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.max'
spectre_expect 'ZuceHazwLojz8!'         -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tlong   -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.long'
spectre_expect 'Boxj2!YabePodp'         -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tlong   -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.⛄'
spectre_expect 'PeblLuqc6]Cala'         -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest'          -c4294967295 -a0 -p 'authentication' -C '' 'ẗesẗ.c+a0pa'
spectre_expect 'XelQac0@'               -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tmed    -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.med'
spectre_expect 'qS07SRc8'               -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tbasic  -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.basic'
spectre_expect 'Fih8'                   -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tshort  -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.short'
spectre_expect '6121'                   -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tpin    -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.pin'
spectre_expect 'rivfutipe'              -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tname   -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.name'
spectre_expect 'xir qebdohogo buno'     -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tphrase -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.phrase'
spectre_expect "RoAm3bJSvo@#loHSRA6\'"  -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tmax    -c1 -a0 -p 'identification' -C ''          'ẗesẗ.c1a0pi.max'
spectre_expect 'biqwaxilu'              -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tnone   -c1 -a0 -p 'identification' -C ''          'ẗesẗ.c1a0pi'
spectre_expect 'ragcoxudo'              -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tname   -c1 -a0 -p 'identification' -C ''          'ẗesẗ.c1a0pi'
spectre_expect 'm8]SiJHiAS@H@Rbw))34'   -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tmax    -c1 -a0 -p 'recovery'       -C ''          'ẗesẗ.c1a0pr.max'
spectre_expect 'kokl hov lowmaya xaf'   -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest'          -c1 -a0 -p 'recovery'       -C ''          'ẗesẗ.c1a0pr'
spectre_expect 'wi zanmu nug zuwidwe'   -Fflat -R0 \
    -u 'tesẗ.v0' -S 'ẗest'          -c1 -a0 -p 'recovery'       -C 'quesẗion'  'ẗesẗ.c1a0pr.quesẗion'


##  V3
printf "\nV%d, json: " 3
spectre_expect 'IfHuAUUpqpKZDZlNvz8$'   -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tmax    -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.max'
spectre_expect 'FamiJirk1)Zehc'         -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tlong   -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.long'
spectre_expect 'NofhMusw8+Cebo'         -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tlong   -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.⛄'
spectre_expect 'Necx1$LagaRizu'         -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest'          -c4294967295 -a3 -p 'authentication' -C '' 'ẗesẗ.c+a3pa'
spectre_expect 'Poq2)Tey'               -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tmed    -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.med'
spectre_expect 'Wr07Okx0'               -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tbasic  -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.basic'
spectre_expect 'Bug9'                   -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tshort  -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.short'
spectre_expect '3560'                   -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tpin    -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.pin'
spectre_expect 'jupxiqepi'              -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tname   -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.name'
spectre_expect 'vuh buxtukewo puhe'     -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tphrase -c1 -a3 -p 'authentication' -C ''          'ẗesẗ.c1a3pa.phrase'
spectre_expect 'Cq5$TfH#OHmPS9yREp7)'   -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tmax    -c1 -a3 -p 'identification' -C ''          'ẗesẗ.c1a3pi.max'
spectre_expect 'secgudiho'              -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tnone   -c1 -a3 -p 'identification' -C ''          'ẗesẗ.c1a3pi'
spectre_expect 'mophabiwe'              -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tname   -c1 -a3 -p 'identification' -C ''          'ẗesẗ.c1a3pi'
spectre_expect 'lA^ul!%9&TD%fj6icT1['   -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest' -tmax    -c1 -a3 -p 'recovery'       -C ''          'ẗesẗ.c1a3pr.max'
spectre_expect 'mup wulbezaxa juca'     -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest'          -c1 -a3 -p 'recovery'       -C ''          'ẗesẗ.c1a3pr'
spectre_expect 'molg rux kaczuvi ror'   -Fjson -R0 \
    -u 'tesẗ.v3' -S 'ẗest'          -c1 -a3 -p 'recovery'       -C 'quesẗion'  'ẗesẗ.c1a3pr.quesẗion'

##  V2
printf "\nV%d, json: " 2
spectre_expect 'i7@0M*DdP4DgD#jJIzyL'   -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tmax    -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.max'
spectre_expect 'Lifw5]DablSuga'         -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tlong   -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.long'
spectre_expect 'Leja5%RavoZapa'         -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tlong   -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.⛄'
spectre_expect 'NejnGazo8?Seqo'         -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest'          -c4294967295 -a2 -p 'authentication' -C '' 'ẗesẗ.c+a2pa'
spectre_expect 'XicSux2&'               -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tmed    -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.med'
spectre_expect 'uEY50hcZ'               -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tbasic  -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.basic'
spectre_expect 'Jif6'                   -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tshort  -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.short'
spectre_expect '4001'                   -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tpin    -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.pin'
spectre_expect 'rexmibace'              -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tname   -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.name'
spectre_expect 'cez fexlemozo yula'     -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tphrase -c1 -a2 -p 'authentication' -C ''          'ẗesẗ.c1a2pa.phrase'
spectre_expect 'T8+xi4NMd3HUGdV#GW*%'   -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tmax    -c1 -a2 -p 'identification' -C ''          'ẗesẗ.c1a2pi.max'
spectre_expect 'nidcepede'              -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tnone   -c1 -a2 -p 'identification' -C ''          'ẗesẗ.c1a2pi'
spectre_expect 'camfibeye'              -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tname   -c1 -a2 -p 'identification' -C ''          'ẗesẗ.c1a2pi'
spectre_expect 'YLcoWeBwyiBf2*irFq1.'   -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest' -tmax    -c1 -a2 -p 'recovery'       -C ''          'ẗesẗ.c1a2pr.max'
spectre_expect 'ye vemcu keq xepewmi'   -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest'          -c1 -a2 -p 'recovery'       -C ''          'ẗesẗ.c1a2pr'
spectre_expect 'yi qazne tid najuvme'   -Fjson -R0 \
    -u 'tesẗ.v2' -S 'ẗest'          -c1 -a2 -p 'recovery'       -C 'quesẗion'  'ẗesẗ.c1a2pr.quesẗion'

##  V1
printf "\nV%d, json: " 1
spectre_expect 'a3~AiGkHk)Pgjbb)mk6H'   -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tmax    -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.max'
spectre_expect 'Lojz6?VotaJall'         -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tlong   -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.long'
spectre_expect 'Yoqu7)NiziFito'         -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tlong   -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.⛄'
spectre_expect 'Foha4[TojmXanc'         -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest'          -c4294967295 -a1 -p 'authentication' -C '' 'ẗesẗ.c+a1pa'
spectre_expect 'Hiy3*Zag'               -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tmed    -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.med'
spectre_expect 'UJR7HpG0'               -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tbasic  -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.basic'
spectre_expect 'Cij7'                   -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tshort  -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.short'
spectre_expect '0020'                   -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tpin    -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.pin'
spectre_expect 'vadxovezu'              -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tname   -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.name'
spectre_expect 'sij jihloyenu kizi'     -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tphrase -c1 -a1 -p 'authentication' -C ''          'ẗesẗ.c1a1pa.phrase'
spectre_expect 'z2U9)(uQ78TXqtaus)8.'   -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tmax    -c1 -a1 -p 'identification' -C ''          'ẗesẗ.c1a1pi.max'
spectre_expect 'wexducuvi'              -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tnone   -c1 -a1 -p 'identification' -C ''          'ẗesẗ.c1a1pi'
spectre_expect 'qipberize'              -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tname   -c1 -a1 -p 'identification' -C ''          'ẗesẗ.c1a1pi'
spectre_expect 'QMciaKyi1&I*g%tHz99,'   -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest' -tmax    -c1 -a1 -p 'recovery'       -C ''          'ẗesẗ.c1a1pr.max'
spectre_expect 'sok torxibute reza'     -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest'          -c1 -a1 -p 'recovery'       -C ''          'ẗesẗ.c1a1pr'
spectre_expect 'xacp qaw qutbece gan'   -Fjson -R0 \
    -u 'tesẗ.v1' -S 'ẗest'          -c1 -a1 -p 'recovery'       -C 'quesẗion'  'ẗesẗ.c1a1pr.quesẗion'

##  V0
printf "\nV%d, json: " 0
spectre_expect 'b5@ww@Jmb4cAioRbivb)'   -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tmax    -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.max'
spectre_expect 'ZuceHazwLojz8!'         -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tlong   -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.long'
spectre_expect 'Boxj2!YabePodp'         -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tlong   -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.⛄'
spectre_expect 'PeblLuqc6]Cala'         -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest'          -c4294967295 -a0 -p 'authentication' -C '' 'ẗesẗ.c+a0pa'
spectre_expect 'XelQac0@'               -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tmed    -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.med'
spectre_expect 'qS07SRc8'               -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tbasic  -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.basic'
spectre_expect 'Fih8'                   -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tshort  -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.short'
spectre_expect '6121'                   -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tpin    -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.pin'
spectre_expect 'rivfutipe'              -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tname   -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.name'
spectre_expect 'xir qebdohogo buno'     -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tphrase -c1 -a0 -p 'authentication' -C ''          'ẗesẗ.c1a0pa.phrase'
spectre_expect "RoAm3bJSvo@#loHSRA6\'"  -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tmax    -c1 -a0 -p 'identification' -C ''          'ẗesẗ.c1a0pi.max'
spectre_expect 'biqwaxilu'              -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tnone   -c1 -a0 -p 'identification' -C ''          'ẗesẗ.c1a0pi'
spectre_expect 'ragcoxudo'              -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tname   -c1 -a0 -p 'identification' -C ''          'ẗesẗ.c1a0pi'
spectre_expect 'm8]SiJHiAS@H@Rbw))34'   -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest' -tmax    -c1 -a0 -p 'recovery'       -C ''          'ẗesẗ.c1a0pr.max'
spectre_expect 'kokl hov lowmaya xaf'   -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest'          -c1 -a0 -p 'recovery'       -C ''          'ẗesẗ.c1a0pr'
spectre_expect 'wi zanmu nug zuwidwe'   -Fjson -R0 \
    -u 'tesẗ.v0' -S 'ẗest'          -c1 -a0 -p 'recovery'       -C 'quesẗion'  'ẗesẗ.c1a0pr.quesẗion'


# Finish
printf '\nDone!\n'
exit "$errors"
