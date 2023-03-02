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
from pathlib import Path
import sys

# FIXME:
sys.path.append('../sarif-dump')
from sarifdump import GccStyleDumper

from results import get_classifier, get_sarif_paths, get_comparable_result, get_comparable_results

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
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--classification-file', type=Path, required=False)
    parser.add_argument('--rule-id', type=str, required=False)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    args = parser.parse_args()
    classifier = get_classifier(args.classification_file)

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
                            verbose=args.verbose,
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
