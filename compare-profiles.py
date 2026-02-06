#!/usr/bin/python3
#   Copyright 2023-2026 David Malcolm <dmalcolm@redhat.com>
#   Copyright 2023-2026 Red Hat, Inc.
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
import statistics
import sys

from projects import get_projects
from results import get_classifier, get_comparable_result, ProjectBuild

class ComparisonConfig:
    def __init__(self, abs_src_dir, projects, before_build_dir, after_build_dir):
        self.abs_src_dir = abs_src_dir
        self.projects = projects
        self.before_build_dir = before_build_dir
        self.after_build_dir = after_build_dir
        self.classifier_by_project = {}
        for project in self.projects:
            self.classifier_by_project[project] = project.get_classifier(self)

    def classify(self, proj, sarif_path, result):
        classifier = self.classifier_by_project[proj]
        return classifier.classify(sarif_path, result)

def print_comparison(heading, before, after):
    print(heading)
    print('  before: %r' % before)
    print('   after: %r' % after)
    print()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--rule-id', type=str, required=False)
    parser.add_argument('--projects', required=False, nargs="+", metavar='PROJNAME',
                        help="If provided, restrict to just the named project(s)")
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    args = parser.parse_args()
    projects = get_projects(args.projects)

    abs_src_dir = Path(sys.argv[0]).parent.absolute()
    config = ComparisonConfig(abs_src_dir, projects, args.before, args.after)
    sarif_schema = None

    def filter_rule(result):
        if args.rule_id:
            ruleId = result.get('ruleId', '')
            if ruleId != args.rule_id:
                return False;
        return True

    slowest = []
    SLOW_THRESHOLD = 600 # 10 minutes

    before_stats = []
    after_stats = []
    for proj in projects:
        before = ProjectBuild(proj, Path(config.before_build_dir, proj.name))
        after  = ProjectBuild(proj, Path(config.after_build_dir, proj.name))
        before_sarif_paths = before.get_rel_sarif_paths()
        after_sarif_paths = after.get_rel_sarif_paths()
        shared_sarif_paths = set()
        shared_sarif_paths |= before_sarif_paths
        shared_sarif_paths &= after_sarif_paths
        for rel_sarif_path in sorted(shared_sarif_paths):
            before_results, before_result_dict, before_failures, before_profiles \
                = before.get_comparable_results(rel_sarif_path, sarif_schema)
            after_results, after_result_dict, after_failures, after_profiles \
                = after.get_comparable_results(rel_sarif_path, sarif_schema)
            if before_profiles:
                stat = before_profiles[0].analyzer_total['wall']
                before_stats.append(stat)
                if stat > SLOW_THRESHOLD:
                    slowest.append(('before', stat, rel_sarif_path))
            if after_profiles:
                stat = after_profiles[0].analyzer_total['wall']
                after_stats.append(stat)
                if stat > SLOW_THRESHOLD:
                    slowest.append(('after', stat, rel_sarif_path))

    print('Wallclock times for analyzer total')
    print('==================================\n')
    print_comparison('deciles',
                     statistics.quantiles(before_stats, n=10),
                     statistics.quantiles(after_stats, n=10))

    print_comparison('mean',
                     statistics.mean(before_stats),
                     statistics.mean(after_stats))

    print_comparison('stdev',
                     statistics.stdev(before_stats),
                     statistics.stdev(after_stats))

    print_comparison('median',
                     statistics.median(before_stats),
                     statistics.median(after_stats))

    print_comparison('maximum',
                     max(before_stats),
                     max(after_stats))

    print('slowest')
    print('  before: %r' % sorted(before_stats)[-5:])
    print('   after: %r' % sorted(after_stats)[-5:])
    if slowest:
        print('  %i exceeded %i seconds:' % (len(slowest), SLOW_THRESHOLD))
        for when, stat, rel_sarif_path in slowest:
            print('    %s: %f: %s' % (when, stat, rel_sarif_path))
    print()

    print_comparison('# datapoints',
                     len(before_stats),
                     len(after_stats))

if __name__ == '__main__':
    main()
