# Shared checks for the Git hooks in this directory and for CI.
# POSIX sh and awk only: Git for Windows runs hooks with its bundled bash.

# Prints the problems in a commit message read from stdin; silent when clean.
# Comment lines and everything below the `git commit -v` scissors are ignored.
rosetun_message_problems() {
    LC_ALL=C awk '
        /^# -+ >8 -+$/ { exit }
        /^#/ { next }
        {
            sub(/\r$/, "")
            if (!seen && $0 != "") {
                seen = 1
                subject = $0
            }
            line = tolower($0)
            if (line ~ /co-authored-by|generated (with|by)|claude|anthropic|copilot|chatgpt|openai/ \
                || index($0, "\360\237\244\226") > 0) {
                print "AI attribution is not allowed: " $0
            }
        }
        END {
            if (subject == "") {
                print "the message is empty"
            } else if (subject !~ /^(Merge |Revert "|fixup! |squash! |amend! )/ \
                && subject !~ /^(feat|fix|refactor|docs|test|style|chore|ci|build|perf|revert)(\([A-Za-z0-9_.\/-]+\))?!?: [^ ]/) {
                print "the subject is not a Conventional Commit (type(scope): Summary): " subject
            }
        }
    '
}

# Prints the problems in the staged changes; silent when clean.
rosetun_staged_problems() {
    git diff --cached --name-only --diff-filter=ACMR | LC_ALL=C awk '
        /(^|\/)rules\// || /(^|\/)rosetun-archive(\/|$)/ {
            print $0 ": must not be committed"
            next
        }
        /\.(patch|diff|orig|rej)$/ {
            print $0 ": patch files stay outside the repository"
        }
    '
    git diff --cached -U0 --no-color --no-ext-diff --diff-filter=ACMR | rosetun_added_line_problems
}

# Reads a unified diff on stdin and checks its added lines.
rosetun_added_line_problems() {
    LC_ALL=C awk -v sq="'" -v user="${USERNAME:-${USER:-}}" -v host="${COMPUTERNAME:-}" \
        "$ROSETUN_ADDED_LINES_AWK"
}

# Checks every added line of a unified diff: no long dashes in Fluent files,
# proxy links only with documentation hosts, no local account or machine name.
ROSETUN_ADDED_LINES_AWK='
BEGIN {
    link_re = "(vless|vmess|ss|ssr|trojan|hysteria2|hy2|tuic|anytls|wireguard)://[^ \t\"" sq "<>`()]*"
    user = tolower(user)
    host = tolower(host)
}
function documentation_host(h) {
    return h == "" || h ~ /[{}$%<]/ || h == "localhost" || h == "[::1]" \
        || h == "0.0.0.0" || h == "[::]" || h !~ /[.\[]/ \
        || h ~ /(^|\.)example\.(com|org|net)$/ \
        || h ~ /\.(invalid|test|example|localhost)$/ \
        || h ~ /^127\./ \
        || h ~ /^(192\.0\.2|198\.51\.100|203\.0\.113)\.[0-9]+$/ \
        || h ~ /^\[2001:db8:/
}
function link_host(link,    rest, cut, at, end) {
    rest = substr(link, index(link, "://") + 3)
    cut = match(rest, /[\/?#]/)
    if (cut > 0) rest = substr(rest, 1, cut - 1)
    while ((at = index(rest, "@")) > 0) rest = substr(rest, at + 1)
    if (substr(rest, 1, 1) == "[") {
        end = index(rest, "]")
        return tolower(end > 0 ? substr(rest, 1, end) : rest)
    }
    end = index(rest, ":")
    return tolower(end > 0 ? substr(rest, 1, end - 1) : rest)
}
function names_user(text, separator,    needle, from, at, next_char) {
    needle = "users" separator user
    from = 1
    while ((at = index(substr(text, from), needle)) > 0) {
        next_char = substr(text, from + at - 1 + length(needle), 1)
        if (next_char == "" || index("\\/\"" sq " ", next_char) > 0) return 1
        from += at
    }
    return 0
}
/^\+\+\+ / {
    file = substr($0, 5)
    sub(/^b\//, "", file)
    next
}
/^\+/ {
    line = substr($0, 2)
    sub(/\r$/, "", line)
    if (file ~ /\.ftl$/ && (index(line, "\342\200\224") > 0 || index(line, "\342\200\223") > 0)) {
        print file ": long dash in a Fluent string: " line
    }
    rest = line
    while (match(rest, link_re)) {
        link = substr(rest, RSTART, RLENGTH)
        rest = substr(rest, RSTART + RLENGTH)
        h = link_host(link)
        if (h ~ /^[a-z0-9+=_]+$/ && length(h) >= 16) {
            print file ": encoded proxy link, use a readable one with a documentation host: " link
        } else if (!documentation_host(h)) {
            print file ": proxy link with a real host (" h "), use example.com, .invalid or RFC 5737/3849 addresses"
        }
    }
    lower = tolower(line)
    if (length(user) >= 2 && (names_user(lower, "\\") || names_user(lower, "\\\\") || names_user(lower, "/"))) {
        print file ": path with the local Windows account name"
    }
    if (length(host) >= 4 && index(lower, host) > 0) {
        print file ": the local computer name"
    }
}
'

# Checks the messages of the commits `git rev-list "$@"` names, skipping merges
# and Dependabot, whose bodies quote upstream release notes. Fails on a problem.
rosetun_check_commits() {
    status=0
    for commit in $(git rev-list --no-merges "$@"); do
        case "$(git log -1 --format=%ae "$commit")" in
            *'dependabot[bot]@users.noreply.github.com') continue ;;
        esac
        problems=$(git log -1 --format=%B "$commit" | rosetun_message_problems)
        if [ -n "$problems" ]; then
            printf '%s: %s\n' "$(git log -1 --format='%h %s' "$commit")" "$problems" >&2
            status=1
        fi
    done
    return "$status"
}
