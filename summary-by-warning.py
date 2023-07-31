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
import heapq
import locale
from pathlib import Path
import sys

# FIXME:
sys.path.append('../sarif-dump')
from sarifdump import GccStyleDumper

from projects import get_projects
from results import get_classifier, get_comparable_result, ProjectBuild, Ratings

class Rule(Ratings):
    """
    Stats about how well a particular rule (aka warning) did.
    """
    def __init__(self, rule_id):
        Ratings.__init__(self)
        self.rule_id = rule_id

class Summary:
    def __init__(self, config, verbose, filter_rule):
        self.config = config
        self.verbose = verbose
        self.filter_rule = filter_rule
        self.stats_by_rule_id = {}
        self.num_failures = 0
        self.profiles = []

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
            print(f'{rule.rule_id}: {score * 100:2.2f}% (GOOD: {rule.good} BAD: {rule.bad})')
            for kind in sorted(rule.stats_by_kind):
                print('%12s: %s' % (kind, rule.stats_by_kind[kind]))

        if self.num_failures:
            print(f'FAILURE: {self.num_failures}')

        N = 50
        print(f'{N} slowest analyses:')
        for user, rel_sarif_path, profile in heapq.nlargest(N,
                                                            [(profile.analyzer_total['user'], profile.rel_sarif_path, profile)
                                                             for profile in self.profiles]):
            sys.stdout.write(f'  {rel_sarif_path}:')
            sys.stdout.write(f' {user:.2f}s')
            if user > 60:
                sys.stdout.write(f' ({user/60:.2f}m)')
            sys.stdout.write(f' out of {profile.total["user"]:.2f}s')
            sys.stdout.write(f' ({profile.get_proportion("user") * 100.0:2.2f}%')
            sys.stdout.write(f'; slowdown = {profile.get_slowdown():.2f})\n')
            without_analysis = profile.get_without_analysis()
            print(f'    without -fanalyzer would be: {without_analysis:.2f}s')
            name, amt = profile.get_greatest_analyzer_item()
            print(f'    {name}: {amt:.2f}s')

    def on_failure(self, proj, sarif_path, failure):
        if self.verbose:
            self.report_failure(sarif_path, failure)
        self.num_failures += 1

    def report_failure(self, sarif_path, failure):
        heading = '%s:' % 'FAILURE'
        print('-' * 76)
        print(heading)
        print('-' * 76)
        print(failure)

    def on_profile(self, proj, sarif_path, profile):
        self.profiles.append(profile)
        # TODO: gather some stats as we go?
        #print(profile.json_obj)
        #print(profile.report())
        #print(profile.analyzer_total)
        #print(profile.total)
        #print(f'usr: {profile.get_proportion("user") * 100.0:2.2f}%')

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
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--rule-id', type=str, required=False)
    parser.add_argument('path', type=Path)
    parser.add_argument('--projects', required=False, nargs="+", metavar='PROJNAME',
                        help="If provided, restrict to just the named project(s)")
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

    summary = Summary(config,
                      verbose=args.verbose,
                      filter_rule=filter_rule)

    for proj in projects:
        proj_build = ProjectBuild(proj, Path(config.run_dir, proj.name))
        sarif_paths = proj_build.get_rel_sarif_paths()
        for rel_sarif_path in sorted(sarif_paths):
            results, result_dict, failures, profiles = \
                proj_build.get_comparable_results(rel_sarif_path)
            for str_result in sorted(results):
                result = result_dict[str_result]
                summary.on_result(proj, proj_build.get_path(rel_sarif_path), result)
            for failure in sorted(failures):
                summary.on_failure(proj, proj_build.get_path(rel_sarif_path), failure)
            for profile in profiles:
                summary.on_profile(proj, proj_build.get_path(rel_sarif_path), profile)

    summary.report_summary()

if __name__ == '__main__':
    main()
