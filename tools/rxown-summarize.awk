BEGIN {
    OFS = ","
    print "file", "sequence", "router_epoch", "uptime_seconds", \
          "mem_available_kb", "pagefrag_allocinfo_bytes", "records", \
          "scoped_records", "allocations", "scoped_allocations", \
          "unscoped_allocations", "head_fragment_releases", \
          "tracked_pages", "tracked_backing_bytes", \
          "tracked_aligned_bytes", "tracked_slack_bytes", \
          "single_ring_pages", "cross_ring_pages", \
          "ring_unscoped_pages", "unscoped_only_pages", \
          "history_cross_lifetime_pages", "history_same_ring_pages", \
          "unscoped_current", "global_idr_remove_unmatched", \
          "ring_count", "actual_idr_total", "ring_allocations", \
          "ring_posts", "ring_reaps", "ring_fragment_releases", \
          "ring_untracked_removes", "allocated_current", \
          "posted_current", "reaped_current", \
          "posted_unique_pages_sum_not_physical", \
          "posted_backing_sum_not_physical", "critical_failures", \
          "nmissed_total", "scope_context_mismatches"
}

function parse_values(line,    count, fields, i, pair) {
    delete value
    count = split(line, fields, /[[:space:]]+/)
    for (i = 1; i <= count; i++) {
        split(fields[i], pair, "=")
        if (length(pair[1]) && length(pair[2]))
            value[pair[1]] = pair[2]
    }
}

function reset_snapshot() {
    router_epoch = uptime_seconds = mem_available_kb = pagefrag_bytes = 0
    records = scoped_records = allocations = scoped_allocations = 0
    unscoped_allocations = head_fragment_releases = 0
    tracked_pages = tracked_backing = tracked_aligned = tracked_slack = 0
    single_ring = cross_ring = ring_unscoped = unscoped_only = 0
    history_cross = history_same = unscoped_current = 0
    global_unmatched = ring_count = actual_idr_total = 0
    ring_allocations = ring_posts = ring_reaps = ring_releases = 0
    ring_untracked = allocated_current = posted_current = reaped_current = 0
    posted_unique_sum = posted_backing_sum = critical_failures = 0
    nmissed_total = context_mismatches = 0
}

function emit_snapshot() {
    if (!active)
        return
    print current_file, sequence, router_epoch, uptime_seconds, \
          mem_available_kb, pagefrag_bytes, records, scoped_records, \
          allocations, scoped_allocations, unscoped_allocations, \
          head_fragment_releases, tracked_pages, tracked_backing, \
          tracked_aligned, tracked_slack, single_ring, cross_ring, \
          ring_unscoped, unscoped_only, history_cross, history_same, \
          unscoped_current, global_unmatched, ring_count, actual_idr_total, \
          ring_allocations, ring_posts, ring_reaps, ring_releases, \
          ring_untracked, allocated_current, posted_current, reaped_current, \
          posted_unique_sum, posted_backing_sum, critical_failures, \
          nmissed_total, context_mismatches
    active = 0
}

FNR == 1 {
    if (NR != 1)
        emit_snapshot()
    current_file = FILENAME
}

/^=== SNAPSHOT / {
    emit_snapshot()
    reset_snapshot()
    parse_values($0)
    sequence = value["sequence"] + 0
    active = 1
    next
}

/^=== RECOVERY / {
    emit_snapshot()
    next
}

active && /^router_epoch=/ {
    parse_values($0)
    router_epoch = value["router_epoch"] + 0
    uptime_seconds = value["uptime_seconds"] + 0
    next
}

active && /^MemAvailable:/ {
    mem_available_kb = $2 + 0
    next
}

active && /mm\/page_alloc.c:[0-9]+ func:__page_frag_cache_refill/ {
    if (!pagefrag_bytes)
        pagefrag_bytes = $1 + 0
    next
}

active && /^records=/ {
    parse_values($0)
    records = value["records"] + 0
    scoped_records = value["scoped_records"] + 0
    next
}

active && /^allocations=/ {
    parse_values($0)
    allocations = value["allocations"] + 0
    scoped_allocations = value["scoped_allocations"] + 0
    unscoped_allocations = value["unscoped_allocations"] + 0
    head_fragment_releases = value["head_fragment_releases"] + 0
    next
}

active && /^tracked_pages=/ {
    parse_values($0)
    tracked_pages = value["tracked_pages"] + 0
    tracked_backing = value["tracked_backing_bytes"] + 0
    tracked_aligned = value["tracked_aligned_bytes"] + 0
    tracked_slack = value["tracked_slack_bytes"] + 0
    next
}

active && /^page_classes / {
    parse_values($0)
    single_ring = value["single_ring"] + 0
    cross_ring = value["cross_ring"] + 0
    ring_unscoped = value["ring_unscoped"] + 0
    unscoped_only = value["unscoped_only"] + 0
    next
}

active && /^page_history / {
    parse_values($0)
    history_cross = value["lower_bound_cross_lifetime_stranded"] + 0
    history_same = value["same_ring_only_in_tracking_window"] + 0
    next
}

active && /^unscoped / {
    parse_values($0)
    unscoped_current = value["current"] + 0
    next
}

active && /^failures / {
    parse_values($0)
    global_unmatched = value["idr_remove_unmatched"] + 0
    critical_failures = value["record_alloc"] + value["record_capacity"] + \
        value["page_alloc"] + value["page_capacity"] + \
        value["scope_alloc"] + value["ring_capacity"] + \
        value["caller_capacity"] + value["head_collision"] + \
        value["skb_collision"]
    next
}

active && /^observations / {
    parse_values($0)
    context_mismatches = value["scope_context_mismatches"] + 0
    next
}

active && /^nmissed / {
    parse_values($0)
    for (name in value)
        if (name != "nmissed")
            nmissed_total += value[name] + 0
    next
}

active && /^ring / {
    parse_values($0)
    ring_count++
    actual_idr_total += value["actual_idr"] + 0
    ring_allocations += value["allocations"] + 0
    ring_posts += value["posts"] + 0
    ring_reaps += value["reaps"] + 0
    ring_releases += value["fragment_releases"] + 0
    ring_untracked += value["untracked_removes"] + 0
    if (!value["actual_valid"] || value["idr_alloc_failures"] || \
        value["release_while_posted"] || value["known_idr_alloc_unmatched"])
        critical_failures++
    next
}

active && /^ring_state / {
    parse_values($0)
    if (value["state"] == "allocated")
        allocated_current += value["current"] + 0
    else if (value["state"] == "posted") {
        posted_current += value["current"] + 0
        posted_unique_sum += value["unique_pages"] + 0
        posted_backing_sum += value["backing_bytes"] + 0
    } else if (value["state"] == "reaped")
        reaped_current += value["current"] + 0
    next
}

END {
    emit_snapshot()
}
