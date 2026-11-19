"""`windows-noise-report` (stage 9d): everything a Windows guest puts on the lab's wire while it does nothing.

The report reads the capture the lab machine kept and says, for the window in which the guest was left alone, each kind
of frame the wire carried: who sent it, the address and port at the other end, how many frames, which category the observer's
classifier gives it, and when the first and the last came. It adds nothing to the classifier and tolerates nothing: a
frame is `infrastructure` only when `lab_protocol` says so, and any other frame is a finding for the owner, who decides
what, if anything, is allowed. `noise` is `NONE` only when no frame of the window is outside `infrastructure`.
"""

from datetime import datetime, timezone

from . import lab_protocol as wire

SCHEMA = 'rosetun.matrix.windows-noise-report.v1'
REST_LABEL = 'rest'
# The most groups a report keeps for the frames outside the windows (the boot and the set-up of the guest): they are
# context, the window of rest is the report.
OUTSIDE_LIMIT = 200


def _sender(frame):
    if frame.src_mac == wire.MACS['test']:
        return 'test'
    if frame.src_mac == wire.MACS['lab']:
        return 'lab'
    return 'other'


def _kind(frame):
    """(protocol, peer, port or message) of a frame, from its headers only.

    The peer is the other end of the guest's flow: where a frame of the guest goes, and where a frame to the guest came
    from (so the answers of one server are one group, not one for each port the guest used).
    """
    if frame.arp is not None:
        op, _, sender, _, target = frame.arp
        return 'arp', target, {1: 'request', 2: 'reply'}.get(op, 'op-%d' % op)
    if frame.fragment:
        return 'ip-fragment', frame.dst, None
    if frame.family is None:
        return 'ethertype-0x%04x' % frame.ethertype, frame.dst_mac, None
    name = wire.PROTOCOL_NAMES.get(frame.proto, 'ip-%s' % frame.proto)
    if frame.proto in (6, 17):
        return (name, frame.dst, frame.dport) if _sender(frame) != 'lab' else (name, frame.src, frame.sport)
    if frame.icmp is not None:
        return name, frame.dst, '%d/%d' % frame.icmp
    return name, frame.dst, None


def _guest_port(frame):
    """The port the guest uses in a frame of a TCP or UDP flow, whichever way it goes."""
    return frame.dport if _sender(frame) == 'lab' else frame.sport


def _server_name(payload):
    """The server name a TLS ClientHello asks for (the SNI extension), or None; only headers of the hello are read."""
    try:
        if len(payload) < 48 or payload[0] != 0x16 or payload[5] != 1:
            return None
        position = 9 + 2 + 32
        position += 1 + payload[position]
        position += 2 + int.from_bytes(payload[position:position + 2], 'big')
        position += 1 + payload[position]
        end = position + 2 + int.from_bytes(payload[position:position + 2], 'big')
        position += 2
        while position + 4 <= min(end, len(payload)):
            kind = int.from_bytes(payload[position:position + 2], 'big')
            size = int.from_bytes(payload[position + 2:position + 4], 'big')
            position += 4
            if kind == 0:
                length = int.from_bytes(payload[position + 3:position + 5], 'big')
                return payload[position + 5:position + 5 + length].decode('ascii', 'replace')[:96]
            position += size
    except IndexError:
        pass
    return None


def _asked(frame):
    """What a frame of the guest asks for by name: a DNS question to port 53 over UDP or the SNI of a TLS hello."""
    if frame.sport is None or _sender(frame) != 'test':
        return None
    if frame.proto == 17 and frame.dport == 53:
        try:
            _, _, name, qtype, _, _ = wire.dns_question(frame.payload)
        except ValueError:
            return None
        return 'dns_questions', '%s %s' % (name[:96], wire.DNS_TYPES.get(qtype, qtype))
    if frame.proto == 6 and frame.dport == 443 and frame.payload:
        name = _server_name(frame.payload)
        return None if name is None else ('tls_server_names', name)
    return None


def _utc(seconds):
    return None if seconds is None else datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec='milliseconds')


def _groups(rows, origin):
    """The frames grouped by sender, kind and category, in the order their first frame came."""
    table = {}
    for _, at, frame, _, category in rows:
        protocol, peer, port = _kind(frame)
        key = (_sender(frame), protocol, peer, port, category)
        row = table.get(key)
        if row is None:
            row = table[key] = dict(sender=key[0], protocol=protocol, peer=peer, port=port,
                                    category=category, frames=0, bytes=0, source_ports=set(), first_at=at, last_at=at,
                                    asked={})
        row['frames'] += 1
        row['bytes'] += frame.size
        if frame.sport is not None:
            row['source_ports'].add(_guest_port(frame))
        asked = _asked(frame)
        if asked is not None:
            names = row['asked'].setdefault(asked[0], {})
            names[asked[1]] = names.get(asked[1], 0) + 1
        if at is not None:
            row['first_at'] = at if row['first_at'] is None else min(row['first_at'], at)
            row['last_at'] = at if row['last_at'] is None else max(row['last_at'], at)
    result = []
    for row in table.values():
        ports = row.pop('source_ports')
        first, last = row.pop('first_at'), row.pop('last_at')
        # What the guest asked for by name, as the frames say it: context for the finding, never a classification.
        row.update({kind: dict(sorted(names.items())) for kind, names in row.pop('asked').items()})
        row.update(flows=len(ports) if row['protocol'] in ('tcp', 'udp') else None,
                   first_seconds=None if first is None or origin is None else round(first - origin, 3),
                   last_seconds=None if last is None or origin is None else round(last - origin, 3),
                   first_utc=_utc(first), last_utc=_utc(last))
        result.append(row)
    result.sort(key=lambda row: (row['first_seconds'] is None, row['first_seconds'] or 0, row['sender'],
                                 row['protocol'], str(row['peer']), str(row['port'])))
    return result


def report(raw, lab_id, *, probes=(), https=None, label=REST_LABEL, limit=wire.CAPTURE_LIMIT):
    """The report of the window labelled `label`, and of what came before the first window, from the lab's capture."""
    try:
        rows, unparsed, problem, labels = wire.classified_frames(raw, lab_id, probes=probes, https=https, limit=limit)
    except ValueError as error:
        return dict(schema=SCHEMA, noise='UNVERIFIED', reason='classification-failed:' + str(error)[:48], window=None,
                    groups=[], unexpected=[], other=[], outside=None, frames=None)
    marks = {}
    for position, at, frame, index, category in rows:
        if category == 'marker':
            marks.setdefault(index, []).append(at)
    found = [index for index, name in sorted(labels.items()) if name == label]
    base = dict(schema=SCHEMA, unparsed_frames=unparsed, capture_problem=problem)
    if len(found) != 1 or any(at is None for at in marks.get(found[0], [None])):
        return dict(base, noise='UNVERIFIED', reason='window-missing' if not found else 'window-repeated-or-untimed',
                    window=None, groups=[], unexpected=[], other=[], outside=None, frames=None)
    index = found[0]
    opened, closed = min(marks[index]), max(marks[index])
    inside = [row for row in rows if row[3] == index and row[4] != 'marker']
    first_marker = min(row[0] for row in rows if row[4] == 'marker')
    before = [row for row in rows if row[0] < first_marker]
    groups = _groups(inside, opened)
    counts = {}
    for row in inside:
        counts[row[4]] = counts.get(row[4], 0) + 1
    start = next((row[1] for row in rows if row[1] is not None), None)
    outside = _groups(before, start)
    unexpected = [row for row in groups if row['category'] == 'unexpected']
    other = [row for row in groups if row['category'] not in ('infrastructure', 'unexpected')]
    noise = 'NONE' if all(row['category'] == 'infrastructure' for row in groups) else 'FOUND'
    return dict(base, noise=noise, reason=None, run=lab_id,
                window=dict(label=label, index=index, opened_utc=_utc(opened), closed_utc=_utc(closed),
                            seconds=round(closed - opened, 3)),
                frames=dict(total=len(inside), by_category=dict(sorted(counts.items()))),
                groups=groups, unexpected=unexpected, other=other,
                outside=dict(frames=len(before), seconds_from='capture-start', groups=outside[:OUTSIDE_LIMIT],
                             groups_omitted=max(0, len(outside) - OUTSIDE_LIMIT)))


def table(document):
    """The groups of a report as short lines of text, for a summary: sender, protocol, peer, port, frames, class, times.

    A group that asked for names (DNS questions, TLS server names) is followed by an indented line with them.
    """
    header = '%-5s %-9s %-40s %-8s %6s  %-24s %9s %9s' % ('from', 'protocol', 'peer', 'port', 'frames', 'class',
                                                          'first(s)', 'last(s)')
    lines = [header]
    for row in document['groups']:
        lines.append('%-5s %-9s %-40s %-8s %6d  %-24s %9s %9s' % (
            row['sender'], row['protocol'], row['peer'], '-' if row['port'] is None else row['port'],
            row['frames'], row['category'], row['first_seconds'], row['last_seconds']))
        for kind in ('dns_questions', 'tls_server_names'):
            if row.get(kind):
                lines.append('      %s: %s' % (kind, ', '.join('%s x%d' % item for item in row[kind].items())))
    return lines
