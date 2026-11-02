# Home DNS blocklist

One AdGuard Home subscription built from AdGuard DNS filter, OISD Full, 1Hosts
Lite, and Steven Black. The build runs away from the router.

Subscribe to:

```text
https://raw.githubusercontent.com/joshuarossi/home-dns-blocklist/main/dist/blocklist.txt
```

The updater downloads all four sources before publishing anything, removes exact
duplicate rules, and removes plain subdomain blocks already covered by a plain
parent-domain block. It retains exception rules, regexes, modifiers, and hosts
entries. Hosts entries stay exact-host entries; they are not broadened into
wildcard blocks. Parent blocks disabled by badfilter are excluded from pruning,
so their child rules remain intact.

Each source must pass basic content and size checks. Large unexpected output
or individual-source reductions fail the build. A failed build leaves the last published version in
place. `dist/manifest.json` records source hashes, counts, output hashes, and the
build time. Source attribution is preserved alongside the feed. If the merged
rules are unchanged, the published feed stays byte-for-byte identical, avoiding
timestamp-only changes that would trigger an unnecessary AdGuard rebuild.

## Build and test

Python 3.11 or newer is sufficient. No third-party packages are required.

```sh
python3 -m unittest -v
python3 build.py
```

The GitHub workflow refreshes the list daily and can also be run manually. AdGuard
Home can retain its normal 24-hour update interval.

## Owner-controlled rules

Edit `custom-rules.txt` to add reviewed blocking rules or exceptions. These rules
are merged with the four upstream sources. Initially it contains only
`||rossi-refresh-test.invalid^`, a reserved-domain health check for confirming that
the feed is active and testing a real in-place update. It cannot block a real
public website. Saving a change to this file triggers a GitHub rebuild automatically. You can
also run the workflow manually or wait for the daily build. Browsing history is
not part of this file.

## Router change and rollback

Keep the original four list entries disabled after enabling the consolidated
subscription. To roll back, disable this subscription and re-enable those four.
Preserve the same cache, upstream DNS, and other filtering settings during the
comparison. Fewer input rules do not guarantee a proportional RAM reduction;
measure memory during a refresh on the actual router.

## Later refinement

Version one consolidates the current sources. It does not select rules based on
browsing history. Any later traffic-based analysis should remain private and keep
an explicit baseline for devices or domains that have not appeared in observations.

See [source attribution](SOURCES.md). The script license applies to the scripts
only; upstream list data retains its own terms.
