#!/usr/bin/env python3
"""Merge published DNS lists without expanding hosts or changing special rules."""

import argparse
import concurrent.futures
import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parent
SIMPLE = re.compile(r"\|\|([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\^")
BADFILTER = re.compile(r"(?:\$|,)badfilter(?:,|$)")
MAX_BYTES = 32 * 1024 * 1024


def plain_domain(rule):
    """Recognize only unconditional domain-and-subdomain blocks."""
    match = SIMPLE.fullmatch(rule)
    if not match:
        return None
    domain = match[1].lower()
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    return None


def read_rules(text):
    if '<html' in text[:2048].lower() or '<!doctype html' in text[:2048].lower():
        raise ValueError('Source returned HTML instead of a filter list')
    rules, notices = [], []
    for raw in text.removeprefix('\ufeff').splitlines():
        line = raw.strip()
        if line.startswith('!#'):
            raise ValueError('Conditional/include directives need explicit handling')
        if not line:
            continue
        if line.startswith(('!', '#')):
            notices.append(line)
            continue
        if line.lower().startswith('[adblock'):
            continue
        if len(line) > 16384:
            raise ValueError('Unexpectedly long filter rule')
        rules.append(line)
    return rules, notices


def merge(rule_groups):
    """Deduplicate and prune only plain suffix rules covered by another plain rule.

    Hosts entries, exceptions, regexes, IP mappings, and modifier rules are retained.
    A plain parent disabled by badfilter is never used to prune child rules.
    Duplicate ordering is stable across all sources.
    """
    unique = dict.fromkeys(rule for group in rule_groups for rule in group)
    badfilters = [rule for rule in unique if BADFILTER.search(rule)]
    disabled_parents = set()
    for rule in badfilters:
        pattern, _, modifiers = rule.rpartition('$')
        remaining = [part for part in modifiers.split(',') if part != 'badfilter']
        if not remaining and (domain := plain_domain(pattern)):
            disabled_parents.add(domain)
    domains = {domain for rule in unique if (domain := plain_domain(rule))}
    covering_domains = domains - disabled_parents
    shadowed = set()
    for domain in domains:
        labels = domain.split('.')
        if any('.'.join(labels[i:]) in covering_domains for i in range(1, len(labels))):
            shadowed.add(domain)
    result = [rule for rule in unique if plain_domain(rule) not in shadowed]
    stats = {
        'input_rule_lines': sum(len(group) for group in rule_groups),
        'exact_duplicates_removed': sum(len(group) for group in rule_groups) - len(unique),
        'redundant_plain_subdomain_rules_removed': len(shadowed),
        'badfilter_rules_preserved': len(badfilters),
        'disabled_plain_parents_excluded_from_pruning': len(disabled_parents),
        'output_rule_lines': len(result),
        'exception_rules_preserved': sum(rule.startswith('@@') for rule in result),
    }
    return result, stats


def download(source, cache_dir=None):
    if cache_dir:
        raw = (cache_dir / (source['name'] + '.txt')).read_bytes()
    else:
        request = urllib.request.Request(source['url'], headers={'User-Agent': 'RossiDNSList/1.0'})
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError(source['name'] + ': source exceeds size limit')
    rules, notices = read_rules(raw.decode('utf-8-sig'))
    if len(rules) < source['minimum_rules']:
        raise ValueError(source['name'] + ': source is unexpectedly small')
    metadata = {
        'name': source['name'], 'url': source['url'], 'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(), 'rule_lines': len(rules),
    }
    return rules, notices, metadata


def write_atomic(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False, encoding='utf-8') as f:
        f.write(content)
        temporary = Path(f.name)
    temporary.replace(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'sources.json')
    parser.add_argument('--cache-dir', type=Path, help='Offline source files named after each source')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist')
    args = parser.parse_args(argv)
    config = json.loads(args.config.read_text())
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        fetched = list(pool.map(lambda source: download(source, args.cache_dir), config['sources']))
    groups = [entry[0] for entry in fetched]
    rules, stats = merge(groups)
    if not rules or stats['exception_rules_preserved'] != len({r for g in groups for r in g if r.startswith('@@')}):
        raise ValueError('Output is empty or an exception rule was lost')
    previous = args.output_dir / 'manifest.json'
    old = None
    if previous.exists():
        old = json.loads(previous.read_text())
        if len(rules) < old['output_rule_lines'] * 0.7:
            raise ValueError('Output shrank by more than 30%; retaining the published list for review')
        previous_sources = {source['name']: source for source in old.get('sources', [])}
        for _, _, source in fetched:
            before = previous_sources.get(source['name'])
            if before and source['rule_lines'] < before['rule_lines'] * 0.7:
                raise ValueError(source['name'] + ': source shrank by more than 30%; review required')
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    body = '\n'.join(rules) + '\n'
    digest = hashlib.sha256(body.encode()).hexdigest()
    header = [
        '! Title: ' + config['name'],
        '! Description: Four existing DNS lists, consolidated without broadening hosts rules.',
        '! Homepage: https://github.com/joshuarossi/home-dns-blocklist',
        '! Expires: 1 day',
        '! Generated: ' + now,
        '! Rule lines: ' + str(len(rules)),
        '! Rule SHA256: ' + digest,
        '! Upstream notices and licenses: source-notices.txt and SOURCES.md in this repository.',
    ]
    header += ['! Source: ' + source['url'] for source in config['sources']]
    blocklist = '\n'.join(header) + '\n\n' + body
    manifest = {'name': config['name'], 'generated_at': now, 'checked_at': now, **stats, 'rules_sha256': digest,
                'feed_sha256': hashlib.sha256(blocklist.encode()).hexdigest(),
                'sources': [entry[2] for entry in fetched]}
    feed_path = args.output_dir / 'blocklist.txt'
    if (old and old.get('rules_sha256') == digest
            and old.get('name', config['name']) == config['name']
            and [source['url'] for source in old.get('sources', [])]
            == [source['url'] for source in config['sources']]
            and feed_path.exists()
            and hashlib.sha256(feed_path.read_bytes()).hexdigest() == old['feed_sha256']):
        # A timestamp-only change would make AdGuard rebuild unchanged rules.
        blocklist = None
        manifest['generated_at'] = old['generated_at']
        manifest['feed_sha256'] = old['feed_sha256']
    notices = []
    for _, comments, metadata in fetched:
        notices += ['SOURCE: ' + metadata['name'], 'URL: ' + metadata['url'], *comments, '']
    # Nothing is written until every source and the entire merged output passes.
    write_atomic(args.output_dir / 'source-notices.txt', '\n'.join(notices) + '\n')
    if blocklist is not None:
        write_atomic(feed_path, blocklist)
    write_atomic(args.output_dir / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
