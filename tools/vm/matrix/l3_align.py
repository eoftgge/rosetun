"""Which flows were open while each scenario of the group ran: a diagnostic of a diagnostic run, never a verdict.

The report of the script gives the duration of every scenario and, once, the time it finished by the clock of
the test machine. It does not give the time any scenario began. The windows give the lab machine's own time
for the markers that open and close a protected session, and the lab machine's clock stamps the flows too.
So a scenario is placed in the window it ran in: after the scenarios of its window that ran before it and
before those that ran after it, which leaves it a stretch as long as the window's slack. Everything here is
approximate and says so; nothing here changes a verdict or an exit code.
"""

from datetime import datetime, timezone
import json
import statistics

from .l3_summary import GROUP, WINDOW_OF

# The most flows of each kind shown for one scenario; the rest are counted.
FLOWS_PER_SCENARIO = 24
_WIRE_FIELDS = ('kind', 'client', 'server', 'frames_out', 'frames_back', 'bytes_out', 'bytes_back', 'first_ms',
                'last_ms', 'syn', 'syn_ack', 'fin', 'rst')
_ROUTE_FIELDS = ('proto', 'client', 'server', 'frames_out', 'frames_back', 'bytes_out', 'bytes_back', 'syn',
                 'syn_ack', 'fin', 'rst')
NOTE = ('approximate: the report has no start time of a scenario; its place is bounded by its window, '
        'in milliseconds after the opening marker of the window by the clock of the lab machine')


def _iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def report_clock(raw):
    """When the script says it finished (seconds since the epoch, the test machine's clock) and how long its cleanup took.

    Either is None when the report does not say, or says something that is not a time: a diagnostic reads
    what it can and never refuses.
    """
    try:
        report = json.loads(raw)
        finished = datetime.strptime(report['finished'], '%Y-%m-%dT%H:%M:%SZ').replace(
            tzinfo=timezone.utc).timestamp()
    except (ValueError, KeyError, TypeError):
        return dict(finished=None, cleanup_ms=None)
    cleanup = report.get('cleanup', {}).get('duration_ms') if type(report.get('cleanup')) is dict else None
    return dict(finished=finished, cleanup_ms=cleanup if type(cleanup) is int and cleanup >= 0 else None)


def report_times(rows, clock):
    """(begin, end) of each scenario by the test machine's clock, counted back from the end of the report.

    The scenarios are taken to follow one another with no pause, which they do not: the pauses between them
    (a connect, a restart) are in no duration, so a scenario is placed later than it ran by the pauses after it.
    """
    if clock['finished'] is None:
        return {}
    end, times = clock['finished'] - (clock['cleanup_ms'] or 0) / 1000, {}
    for row in reversed(rows):
        seconds = (row['duration_ms'] if type(row.get('duration_ms')) is int else 0) / 1000
        times[row['id']] = (end - seconds, end)
        end -= seconds
    return times


def _window_of(label, windows):
    """The first window with this label that has both of its marker times, and how many windows have the label."""
    found = [w for w in windows if w.get('label') == label]
    for window in found:
        clock = window.get('clock') or {}
        if type(clock.get('open_at')) in (int, float) and type(clock.get('close_at')) in (int, float):
            return window, len(found)
    return None, len(found)


def _overlaps(first, last, begin, end):
    return first is None or last is None or (first <= end and last >= begin)


def _pick(rows, begin, end):
    """The rows whose time overlaps [begin, end] (a row with no time is kept, and says so), capped, with the count left out."""
    kept = [dict(row, **({'time_unknown': True} if row['first_ms'] is None or row['last_ms'] is None else {}))
            for row in rows if _overlaps(row['first_ms'], row['last_ms'], begin, end)]
    return kept[:FLOWS_PER_SCENARIO], max(0, len(kept) - FLOWS_PER_SCENARIO)


def align(rows, raw_report, lab):
    """For each scenario of the group: when it ran, and the flows of the wire and of the route link that overlap that.

    `rows` are the scenarios of the report in the order they ran, `raw_report` its bytes (or None) and `lab`
    the summary's `lab` block. Times of a flow are milliseconds after the opening marker of the scenario's
    window, so the wire and the route link can be set side by side.
    """
    by_id = {row['id']: row for row in rows}
    times = report_times(rows, report_clock(raw_report)) if raw_report is not None else {}
    windows = [w for w in lab.get('windows', []) if type(w) is dict]
    route = (lab.get('route_flows') or {}).get('flows', [])
    table, offsets = [], []
    for label in dict.fromkeys(label for label in WINDOW_OF.values() if label):
        window, count = _window_of(label, windows)
        peers = [row for row in rows if WINDOW_OF.get(row['id']) == label]
        if window is None or not peers:
            continue
        first = times.get(peers[0]['id'])
        if first is not None:
            offsets.append(dict(label=label, window=window['index'], count=count,
                                offset_s=round(window['clock']['open_at'] - first[0], 3)))
    values = [row['offset_s'] for row in offsets]
    clock = dict(approximate=True, resolution_s=1, offset_s=round(statistics.median(values), 3) if values else None,
                 spread_s=round(max(values) - min(values), 3) if values else None, by_window=offsets,
                 last_end=_iso(max(end for _, end in times.values())) if times else None)
    for identifier in GROUP:
        row = by_id.get(identifier)
        label = WINDOW_OF[identifier]
        entry = dict(id=identifier, approximate=True, result=row.get('result') if row else 'MISSING',
                     label=label, window=None,
                     windows_with_label=0, duration_ms=row.get('duration_ms') if row else None,
                     report_begin=_iso(times[identifier][0]) if identifier in times else None,
                     report_end=_iso(times[identifier][1]) if identifier in times else None,
                     interval_ms=None, wire_flows=[], wire_omitted=0, route_flows=[], route_omitted=0)
        table.append(entry)
        if row is None or label is None:
            continue
        window, entry['windows_with_label'] = _window_of(label, windows)
        if window is None:
            continue
        peers = [peer for peer in rows if WINDOW_OF.get(peer['id']) == label]
        durations = [peer['duration_ms'] if type(peer.get('duration_ms')) is int else 0 for peer in peers]
        place = [peer['id'] for peer in peers].index(identifier)
        before, after = sum(durations[:place]), sum(durations[place + 1:])
        span = round((window['clock']['close_at'] - window['clock']['open_at']) * 1000)
        begin = min(before, span)
        end = max(begin, span - after)
        entry.update(window=window['index'], interval_ms=dict(
            begin=begin, end=end, slack=span - sum(durations), window_span=span))
        wire = [flow for flow in (window.get('flows') or {}).get('connections', []) if type(flow) is dict]
        entry['wire_flows'], entry['wire_omitted'] = _pick(
            [{k: flow.get(k) for k in _WIRE_FIELDS} for flow in wire], begin, end)
        opened = window['clock']['open_at']
        shifted = [dict({k: flow[k] for k in _ROUTE_FIELDS},
                        first_ms=round((flow['first_at'] - opened) * 1000), last_ms=round((flow['last_at'] - opened) * 1000))
                   for flow in route]
        entry['route_flows'], entry['route_omitted'] = _pick(shifted, begin, end)
    return dict(note=NOTE, clock=clock, scenarios=table)
