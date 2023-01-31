#!/usr/bin/python3
#   Copyright 2023 David Malcolm <dmalcolm@redhat.com>
#   Copyright 2023 Red Hat, Inc.
#
#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
#   USA

import argparse
import io
from pathlib import Path
import re
import sys

import sarif.loader

sys.path.append('../sarif-dump')
from sarifdump import GccStyleDumper

def canonicalize(v):
    v = v.replace('‘', "'")
    v = v.replace('’', "'")
    return v

class ClassificationRule:
    def __init__(self, kind, line):
        self.kind = kind
        self.line = canonicalize(line)

    def __str__(self):
        return '%s: %s' % (self.kind, self.line)

    def matches(self, result):
        #print('considering rule: %s' % self)
        with io.StringIO() as f:
            dumper = GccStyleDumper(f, '')
            dumper.dump_sarif_result(result)
            # FIXME: this is O(N^2)
            v = f.getvalue()
        v = canonicalize(v)
        #print('v: %r' % v)
        #print('self.line: %r' % self.line)
        return self.line in v

class ClassificationFile:
    def __init__(self, path):
        self.rules = []
        with open(path) as f:
            for line in f.readlines():
                line = line.strip()
                #print(repr(line))
                m = re.match('^SKIP: (.+)$', line)
                if m:
                    self.add_rule('SKIP', m.group(1))
                    continue
                m = re.match('^TRUE: (.+)$', line)
                if m:
                    self.add_rule('TRUE', m.group(1))
                    continue
                m = re.match('^FALSE: (.+)$', line)
                if m:
                    self.add_rule('FALSE', m.group(1))
                    continue
                m = re.match('^TODO: (.+)$', line)
                if m:
                    self.add_rule('TODO', m.group(1))
                    continue

    def add_rule(self, kind, line):
        rule = ClassificationRule(kind, line)
        self.rules.append(rule)

    def classify(self, sarif_path, result):
        for rule in self.rules:
            if rule.matches(result):
                return rule.kind
        return 'UNKNOWN'

class JulietClassifer:
    def classify(self, sarif_path, result):
        print(sarif_path)
        manifest_path = Path(sarif_path.parent, 'manifest.sarif')
        manifest_file = sarif.loader.load_sarif_file(manifest_path)
        for expected_result in manifest_file.get_results():
            #print(expected_result)
            # e.g.
            # {'ruleId': 'CWE-415',
            #  'message': {'text': 'Double Free.'},
            #  'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'src/testcases/CWE415_Double_Free/s01/CWE415_Double_Free__malloc_free_char_01.c', 'index': 0}, 'region': {'startLine': 32}}}],
            #  'taxa': [{'toolComponent': {'name': 'CWE', 'index': 0}, 'id': '415', 'index': 0}]}
            print(get_comparable_result(expected_result, sarif_path.parent))
            if self.matches_expected(expected_result, result):
                return 'TRUE'
        return 'FALSE'

    def matches_expected(self, expected_result, actual_result):
        # For now, just check for a location match
        assert len(expected_result['locations']) == 1
        assert len(actual_result['locations']) == 1
        exp_loc = expected_result['locations'][0]
        actual_loc = actual_result['locations'][0]
        #print(exp_phys_loc)
        #print(actual_phys_loc)
        if self.location_matches(exp_loc, actual_loc):
            return True
        # Otherwise, look within paths
        if 'codeFlows' in actual_result:
            assert(len(actual_result['codeFlows']) == 1)
            if 'threadFlows' in actual_result['codeFlows'][0]:
                #print(actual_result['codeFlows'][0]['threadFlows'])
                assert(len(actual_result['codeFlows'][0]['threadFlows']) == 1)
                for thread_flow_loc in actual_result['codeFlows'][0]['threadFlows'][0]['locations']:
                    #print(thread_flow_loc)
                    if self.location_matches(exp_loc, thread_flow_loc['location']):
                        return True
        return False

    def location_matches(self, exp_loc, actual_loc):
        exp_phys_loc = exp_loc['physicalLocation']
        actual_phys_loc = actual_loc['physicalLocation']
        # TODO: compare URI
        if exp_phys_loc['region']['startLine'] != actual_phys_loc['region']['startLine']:
            return False
        return True

def get_sarif_paths(path):
    """
    Get a set of all sarif files below path, relative to path.
    """
    return set([sarif_path.relative_to(path)
                for sarif_path in path.glob('**/*.sarif')
                if sarif_path.name != 'manifest.sarif'])

def get_comparable_result(result, base_src_path):
    with io.StringIO() as f:
        dumper = GccStyleDumper(f, base_src_path)
        dumper.dump_sarif_result(result)
        return f.getvalue()

def get_comparable_results(base_sarif_path, rel_sarif_path):
    """
    """
    str_results = []
    d = {}
    sarif_path = Path(base_sarif_path, rel_sarif_path)
    #base_src_path = sarif_path.parent
    sarif_file = sarif.loader.load_sarif_file(sarif_path)
    for result in sarif_file.get_results():
        s = get_comparable_result(result, '')
        str_results.append(s)
        d[s] = result
    return set(str_results), d

class Comparison:
    def __init__(self, classifier, verbose, filter_rule):
        self.classifier = classifier
        self.verbose = verbose
        self.filter_rule = filter_rule
        self.stats = {}

    def on_new_result(self, sarif_path, result):
        if self.verbose:
            self.report_change('new result:', sarif_path, result)
        self.add_stat('ADDED', sarif_path, result)

    def on_removed_result(self, sarif_path, result):
        if self.verbose:
            self.report_change('result went away:', sarif_path, result)
        self.add_stat('REMOVED', sarif_path, result)

    def on_unchanged_result(self, sarif_path, old_result, new_result):
        if self.verbose:
            self.report_change('unchanged result:', sarif_path, old_result)
        self.add_stat('UNCHANGED', sarif_path, old_result)

    def report_change(self, title, sarif_path, result):
        if self.filter_rule:
            if not self.filter_rule(result):
                return
        heading = title.upper()
        heading += ' %s:' % self.classifier.classify(sarif_path, result)
        if 'ruleId' in result:
            heading += ' %s:' % result['ruleId']
        print('-' * 76)
        print(heading)
        print('-' * 76)
        print(get_comparable_result(result, sarif_path.parent))

    def add_stat(self, event, sarif_path, result):
        if self.filter_rule:
            if not self.filter_rule(result):
                return
        kind = self.classifier.classify(sarif_path, result)
        ruleId = result.get('ruleId', '')
        key = (event, ruleId, kind)
        if key in self.stats:
            self.stats[key] += 1
        else:
            self.stats[key] = 1

    def report_summary(self):
        for key in sorted(self.stats):
            event, ruleId, kind = key
            print(event, ruleId, kind, self.stats[key])

def main():
    parser = argparse.ArgumentParser(
        prog = 'ProgramName',
        description = 'What the program does',
        epilog = 'Text at the bottom of help')
    parser.add_argument('--classification-file', type=Path, required=False)
    parser.add_argument('--rule-id', type=str, required=False)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    args = parser.parse_args()
    if args.classification_file.name == 'Juliet.txt':
        classifier = JulietClassifer()
    elif args.classification_file:
        classifier = ClassificationFile(args.classification_file)
    else:
        classifier = None

    before_sarif_paths = get_sarif_paths(args.before)
    after_sarif_paths = get_sarif_paths(args.after)
    all_sarif_paths = set()
    all_sarif_paths |= before_sarif_paths
    all_sarif_paths |= after_sarif_paths

    def filter_rule(result):
        if args.rule_id:
            ruleId = result.get('ruleId', '')
            if ruleId != args.rule_id:
                return False;
        return True

    comparison = Comparison(classifier,
                            verbose=True,
                            filter_rule=filter_rule)

    for rel_sarif_path in sorted(all_sarif_paths):
        if rel_sarif_path not in after_sarif_paths:
            continue # TODO: sarif file went away
        if rel_sarif_path not in before_sarif_paths:
            continue # TODO: new sarif file appeared
        before_results, before_result_dict = get_comparable_results(args.before, rel_sarif_path)
        after_results, after_result_dict = get_comparable_results(args.after, rel_sarif_path)
        all_results = set()
        all_results |= before_results
        all_results |= after_results
        for str_result in sorted(all_results):
            if str_result not in before_results:
                result = after_result_dict[str_result]
                comparison.on_new_result(Path(args.after, rel_sarif_path), result)
            elif str_result not in after_results:
                result = before_result_dict[str_result]
                comparison.on_removed_result(Path(args.before, rel_sarif_path), result)
            else:
                old_result = before_result_dict[str_result]
                new_result = after_result_dict[str_result]
                comparison.on_unchanged_result(Path(args.before, rel_sarif_path), old_result, new_result)
    comparison.report_summary()

if __name__ == '__main__':
    main()
