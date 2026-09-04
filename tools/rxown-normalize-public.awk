BEGIN {
    FS = OFS = ","
}

NR == 1 {
    printf "cycle,sequence,elapsed_seconds"
    for (field = 4; field <= NF; field++)
        printf ",%s", $field
    printf "\n"
    next
}

{
    cycle = "unknown"
    if (match($1, /cycle[0-9]+/))
        cycle = substr($1, RSTART, RLENGTH)
    if (!(cycle in first_epoch))
        first_epoch[cycle] = $3

    printf "%s,%s,%d", cycle, $2, $3 - first_epoch[cycle]
    for (field = 4; field <= NF; field++)
        printf ",%s", $field
    printf "\n"
}
