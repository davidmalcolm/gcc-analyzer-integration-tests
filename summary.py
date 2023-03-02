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

class Summary:
    def __init__(self, classifier, verbose, filter_rule):
        self.classifier = classifier
        self.verbose = verbose
        self.filter_rule = filter_rule
        self.stats = {}

    def on_result(self, sarif_path, result):
        if self.filter_rule:
            if not self.filter_rule(result):
                return
        kind = self.classifier.classify(sarif_path, result)
        if self.verbose:
            self.report_result(sarif_path, kind, result)
        ruleId = result.get('ruleId', '')
        key = (ruleId, kind)
        if key in self.stats:
            self.stats[key] += 1
        else:
            self.stats[key] = 1

    def report_result(self, sarif_path, kind, result):
        heading = '%s:' % kind
        if 'ruleId' in result:
            heading += ' %s:' % result['ruleId']
        print('-' * 76)
        print(heading)
        print('-' * 76)
        print(get_comparable_result(result, sarif_path.parent))

    def report_summary(self):
        for key in sorted(self.stats):
            ruleId, kind = key
            print(ruleId, kind, self.stats[key])

def main():
    parser = argparse.ArgumentParser(
        prog = 'ProgramName',
        description = 'What the program does',
        epilog = 'Text at the bottom of help')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--classification-file', type=Path, required=False)
    parser.add_argument('--rule-id', type=str, required=False)
    parser.add_argument('path', type=Path)
    args = parser.parse_args()
    classifier = get_classifier(args.classification_file)

    sarif_paths = get_sarif_paths(args.path)

    def filter_rule(result):
        if args.rule_id:
            ruleId = result.get('ruleId', '')
            if ruleId != args.rule_id:
                return False;
        return True

    summary = Summary(classifier,
                      verbose=args.verbose,
                      filter_rule=filter_rule)

    for rel_sarif_path in sorted(sarif_paths):
        results, result_dict = get_comparable_results(args.path, rel_sarif_path)
        for str_result in sorted(results):
            result = result_dict[str_result]
            summary.on_result(Path(args.path, rel_sarif_path), result)

    summary.report_summary()

if __name__ == '__main__':
    main()
