import unittest
import contextlib
import io
import json
from pathlib import Path
import tempfile

from build import main, merge, read_rules


class RuleSemanticsTests(unittest.TestCase):
    def test_exact_duplicates_and_suffix_coverage(self):
        result, stats = merge([['||example.com^', '||ads.example.com^'], ['||example.com^']])
        self.assertEqual(result, ['||example.com^'])
        self.assertEqual(stats['exact_duplicates_removed'], 1)
        self.assertEqual(stats['redundant_plain_subdomain_rules_removed'], 1)

    def test_exceptions_important_rules_and_regex_are_preserved(self):
        special = ['@@||shop.example.com^', '||ads.example.com^$important', '/ads[0-9]+/']
        result, _ = merge([['||example.com^', '||ads.example.com^', *special]])
        self.assertEqual(result, ['||example.com^', *special])

    def test_exact_hosts_entries_are_not_broadened_or_removed(self):
        hosts = ['0.0.0.0 example.com', '0.0.0.0 sub.example.com', '1.2.3.4 other.example.com']
        result, _ = merge([hosts, ['||example.com^']])
        self.assertEqual(result, hosts + ['||example.com^'])

    def test_badfilter_prevents_unsafe_parent_pruning(self):
        rules = ['||example.com^', '||ads.example.com^', '||example.com^$badfilter']
        result, stats = merge([rules])
        self.assertEqual(result, rules)
        self.assertEqual(stats['disabled_plain_parents_excluded_from_pruning'], 1)

    def test_unrelated_badfilter_does_not_prevent_safe_pruning(self):
        rules = ['||example.com^', '||ads.example.com^', '||other.test^$badfilter']
        self.assertEqual(merge([rules])[0], ['||example.com^', '||other.test^$badfilter'])

    def test_disabled_modified_rule_is_not_a_disabled_plain_parent(self):
        rules = ['||example.com^', '||ads.example.com^', '||example.com^$important,badfilter']
        self.assertEqual(merge([rules])[0], ['||example.com^', '||example.com^$important,badfilter'])

    def test_client_scoped_rule_does_not_cover_global_child(self):
        rules = ['||example.com^$client=192.0.2.1', '||ads.example.com^']
        self.assertEqual(merge([rules])[0], rules)

    def test_label_boundaries_are_respected(self):
        rules = ['||example.com^', '||notexample.com^', '||example.com.evil.test^']
        self.assertEqual(merge([rules])[0], rules)

    def test_ip_and_unicode_rules_are_retained(self):
        rules = ['||1.2.3.4^', '||2.3.4^', '||пример.рф^']
        self.assertEqual(merge([rules])[0], rules)

    def test_html_and_unexpanded_directives_fail_closed(self):
        for data in ['<!DOCTYPE html><html>error</html>', '!#include remote.txt']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                read_rules(data)

    def test_comments_are_separated_and_original_case_is_preserved(self):
        rules, comments = read_rules('! attribution\n# license\n||EXAMPLE.com^\n0.0.0.0 Exact.com\n')
        self.assertEqual(rules, ['||EXAMPLE.com^', '0.0.0.0 Exact.com'])
        self.assertEqual(len(comments), 2)

    def test_failed_source_retains_previous_published_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'sources.json'
            config.write_text(json.dumps({'name': 'test', 'sources': [
                {'name': 'test', 'url': 'https://example.test/list', 'minimum_rules': 2}
            ]}))
            (root / 'test.txt').write_text('<html>source failed</html>')
            output = root / 'dist'
            output.mkdir()
            (output / 'blocklist.txt').write_text('previous valid list\n')
            with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
                main(['--config', str(config), '--cache-dir', str(root), '--output-dir', str(output)])
            self.assertEqual((output / 'blocklist.txt').read_text(), 'previous valid list\n')

    def test_unexpected_shrink_retains_previous_published_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'sources.json'
            config.write_text(json.dumps({'name': 'test', 'sources': [
                {'name': 'test', 'url': 'https://example.test/list', 'minimum_rules': 1}
            ]}))
            (root / 'test.txt').write_text('||example.com^\n')
            output = root / 'dist'
            output.mkdir()
            (output / 'blocklist.txt').write_text('previous valid list\n')
            (output / 'manifest.json').write_text(json.dumps({'output_rule_lines': 100}))
            with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
                main(['--config', str(config), '--cache-dir', str(root), '--output-dir', str(output)])
            self.assertEqual((output / 'blocklist.txt').read_text(), 'previous valid list\n')


if __name__ == '__main__':
    unittest.main()
