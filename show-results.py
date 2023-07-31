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
from functools import cmp_to_key
import locale
from pathlib import Path
import sys

# FIXME:
sys.path.append('../sarif-dump')
from sarifdump import GccStyleDumper

from projects import get_projects
from results import get_classifier, get_comparable_result, ProjectBuild, \
    GOOD_KINDS, BAD_KINDS

class Summary:
    def __init__(self, config, verbose, filter_rule):
        self.config = config
        self.verbose = verbose
        self.filter_rule = filter_rule
        self.stats_by_rule_id = {}

    def on_result(self, proj, sarif_path, result):
        if self.filter_rule:
            if not self.filter_rule(result):
                return
        kind = self.config.classify(proj, sarif_path, result)
        if self.verbose:
            self.report_result(sarif_path, kind, result)
        ruleId = result.get('ruleId', '')
        if kind == 'SKIP':
            return
        if ruleId not in self.stats_by_rule_id:
            self.stats_by_rule_id[ruleId] = Rule(ruleId)
        self.stats_by_rule_id[ruleId].on_kind(kind)

    def report_result(self, sarif_path, kind, result):
        heading = '%s:' % kind
        if 'ruleId' in result:
            heading += ' %s:' % result['ruleId']
        print('-' * 76)
        print(heading)
        print('-' * 76)
        print(get_comparable_result(result, sarif_path.parent))

    def report_summary(self):
        def compare_score_lines(sp1, sp2):
            score1, rule1 = sp1
            score2, rule2 = sp2
            # First by score, descending:
            if score1 != score2:
                return score2 - score1
            # Then by rule_id, ascending:
            return locale.strcoll(rule1.rule_id, rule2.rule_id)
        scores = [(rule.get_score(), rule)
                  for rule in self.stats_by_rule_id.values()]
        for score, rule in sorted(scores, key=cmp_to_key(compare_score_lines)):
            print('%s: %2.2f%%' % (rule.rule_id, score * 100))
            for kind in sorted(rule.stats_by_kind):
                print('%12s: %s' % (kind, rule.stats_by_kind[kind]))

class SummaryConfig:
    def __init__(self, abs_src_dir, projects, run_dir):
        self.abs_src_dir = abs_src_dir
        self.projects = projects
        self.run_dir = run_dir
        self.classifier_by_project = {}
        for project in self.projects:
            self.classifier_by_project[project] = project.get_classifier(self)

    def classify(self, proj, sarif_path, result):
        classifier = self.classifier_by_project[proj]
        return classifier.classify(sarif_path, result)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=Path)
    parser.add_argument('--projects', required=False, nargs="+", metavar='PROJNAME',
                        help="If provided, restrict to just the named project(s)")
    parser.add_argument('--rule-id', type=str, required=False,
                        help="If provided, restrict to just the named rule ID")
    parser.add_argument('--kind', type=str, required=False,
                        help="If provided, restrict to just those results classified as KIND")
    args = parser.parse_args()
    projects = get_projects(args.projects)

    abs_src_dir = Path(sys.argv[0]).parent.absolute()
    config = SummaryConfig(abs_src_dir, projects, args.path)

    def filter_rule(result):
        if args.rule_id:
            ruleId = result.get('ruleId', '')
            if ruleId != args.rule_id:
                return False;
        return True

    for proj in projects:
        proj_build = ProjectBuild(proj, Path(config.run_dir, proj.name))
        sarif_paths = proj_build.get_rel_sarif_paths()
        for rel_sarif_path in sorted(sarif_paths):
            results, result_dict = proj_build.get_comparable_results(rel_sarif_path)
            for str_result in sorted(results):
                result = result_dict[str_result]
                if args.rule_id:
                    ruleId = result.get('ruleId', '')
                    if ruleId != args.rule_id:
                        continue
                kind = config.classify(proj, proj_build.get_path(rel_sarif_path), result)
                if args.kind:
                    if kind != args.kind:
                        continue
                heading = '%s:' % kind
                if 'ruleId' in result:
                    heading += ' %s:' % result['ruleId']
                print('-' * 76)
                print(heading)
                print('-' * 76)
                print(get_comparable_result(result,
                                            proj_build.get_path(rel_sarif_path).parent))

if __name__ == '__main__':
    main()
