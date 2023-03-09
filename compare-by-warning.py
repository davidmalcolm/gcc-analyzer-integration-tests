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

from projects import get_projects
from results import get_classifier, get_comparable_result, ProjectBuild, Ratings

DEBUG=0

def describe_change(before, after) -> str:
    result = f'{before}'
    if after != before:
        result += f' -> {after}'
        delta = after - before
        if delta > 0:
            result += f' (+{delta})'
        else:
            result += f' (-{-delta})'
    return result

class RatingChanges:
    def __init__(self):
        self.before = Ratings()
        self.after = Ratings()

    def on_event(self, event: str, kind: str):
        if kind == 'SKIP':
            return
        if event == 'ADDED':
            self.after.on_kind(kind)
        elif event == 'REMOVED':
            self.before.on_kind(kind)
        else:
            assert event == 'UNCHANGED'
            self.before.on_kind(kind)
            self.after.on_kind(kind)

    def describe(self) -> str:
        if self.before.total == 0 and self.after.total == 0:
            return ''
        result = ''
        result += f' {self.before.get_score() * 100:2.2f}%'
        if self.after.get_score() != self.before.get_score():
            result += f' -> {self.after.get_score() * 100:2.2f}%'
        def describe_quality(title, before, after) -> str:
            result = describe_change(before, after)
            if result:
                result = f' {title}: ' + result
            return result
        result += describe_quality('GOOD', self.before.good, self.after.good)
        result += describe_quality('BAD', self.before.bad, self.after.bad)
        return result

class StatsItem:
    def print_item(self, indent):
        raise NotImplementedError

    def print(self, indent, msg):
        print(('  ' * indent) + msg)

class GroupedStats(StatsItem):
    """
    TODO
    """
    def __init__(self):
        self.stats_by_group_key = {}

    def add(self, *args):
        if DEBUG:
            print(f'{self.__class__.__name__}.add({args=})')
        group_key = args[0]
        inner_value = args[1:]
        if DEBUG:
            print(f'{self.__class__.__name__}.add: {group_key=} {inner_value=}')
        if group_key not in self.stats_by_group_key:
            self.stats_by_group_key[group_key] = self.make_group(group_key)
        if DEBUG:
            print(f'adding {inner_value} to {self.stats_by_group_key[group_key]}')
        self.stats_by_group_key[group_key].add(*inner_value)

    def make_group(self, group_key):
        raise NotImplementedError()

    def print_item(self, indent):
        if DEBUG:
            self.print(indent, f'{self}')
        self.print_title(indent)
        if DEBUG:
            self.print(indent, f'{self.stats_by_group_key}')
        for group_key in self.stats_by_group_key: #sorted(self.stats_by_group_key):
            self.stats_by_group_key[group_key].print_item(indent + 1)

class AccumStats(StatsItem):
    """
    TODO
    """
    def __init__(self, desc):
        self.desc = desc
        self.count = 0

    def add(self):
        self.count += 1
        if DEBUG:
            print(f'{self.__class__.__name__}.add(), count now: {self.count}')

    def print_item(self, indent):
        self.print(indent, f'{self.desc}: {self.count}')

class PerEventStats(AccumStats):
    def __init__(self, event):
        AccumStats.__init__(self, event)

    def __str__(self):
        return f'PerEventStats({self.desc!r})'

class GroupedStatsWithEventCount(GroupedStats):
    def __init__(self):
        GroupedStats.__init__(self)
        self.before_count = 0
        self.after_count = 0

    def update_counts_for_event(self, event):
        if DEBUG:
            print(event)
        assert event in {'ADDED', 'REMOVED', 'UNCHANGED'}
        if event == 'ADDED':
            self.after_count += 1
        elif event == 'REMOVED':
            self.before_count += 1
        else:
            self.before_count += 1
            self.after_count += 1

    def print_title(self, indent):
        title = f'{self.get_desc()}: {self.before_count}'
        if self.after_count != self.before_count:
            title += f' -> {self.after_count}'
            delta = self.after_count - self.before_count
            if delta > 0:
                title += f' (+{delta})'
            else:
                title += f' (-{-delta})'
        self.print(indent, title)

class PerProjectStats(GroupedStatsWithEventCount):
    def __init__(self, project):
        GroupedStatsWithEventCount.__init__(self)
        self.project = project

    def __str__(self):
        return f'PerProjectStats({self.project.name!r})'

    def add(self, *args):
        GroupedStats.add(self, *args)
        self.update_counts_for_event(args[0])

    def make_group(self, group_key):
        return PerEventStats(group_key)

    def print_item(self, indent):
        if DEBUG:
            self.print(indent, f'{self}')
        self.print_title(indent)
        if ('UNCHANGED' in self.stats_by_group_key
              and len(self.stats_by_group_key) == 1):
            # Avoid printing lines for purely "UNCHANGED" results
            return
        if DEBUG:
            self.print(indent, f'{self.stats_by_group_key}')
        for group_key in self.stats_by_group_key: #sorted(self.stats_by_group_key):
            self.stats_by_group_key[group_key].print_item(indent + 1)

    def get_desc(self):
        return self.project.name

class PerKindStats(GroupedStatsWithEventCount):
    def __init__(self, kind):
        GroupedStatsWithEventCount.__init__(self)
        self.kind = kind

    def __str__(self):
        return f'PerKindStats({self.kind!r})'

    def add(self, *args):
        GroupedStats.add(self, *args)
        self.update_counts_for_event(args[1])

    def make_group(self, group_key):
        return PerProjectStats(group_key)

    def get_desc(self):
        return self.kind

class PerRuleStats(GroupedStats):
    """
    Stats about how well a particular rule (aka warning) did.
    """

    def __init__(self, rule_id : str):
        GroupedStats.__init__(self)
        self.rating_changes = RatingChanges()
        self.rule_id = rule_id

    def __str__(self):
        return f'PerRuleStats({self.rule_id!r})'

    def make_group(self, group_key):
        return PerKindStats(group_key)

    def add(self, *args):
        GroupedStats.add(self, *args)
        self.rating_changes.on_event(args[2], args[0])

    def print_title(self, indent):
        self.print(indent, f'{self.rule_id}:{self.rating_changes.describe()}')

class Comparison(GroupedStats):
    def __init__(self, classifier, verbose, filter_rule):
        GroupedStats.__init__(self)
        self.rating_changes = RatingChanges()
        self.before_count = 0
        self.after_count = 0
        self.classifier = classifier
        self.verbose = verbose
        self.filter_rule = filter_rule
        self.new_sarif_files = set()
        self.removed_sarif_files = set()

    def on_new_sarif_file(self, proj, rel_sarif_path):
        self.new_sarif_files.add((proj.name, rel_sarif_path))

    def on_removed_sarif_file(self, proj, rel_sarif_path):
        self.removed_sarif_files.add((proj.name, rel_sarif_path))

    def make_group(self, rule_id):
        return PerRuleStats(rule_id)

    def print_title(self, indent):
        self.print(indent,
                   f'Comparison:{self.rating_changes.describe()}')

    def on_new_result(self, proj, sarif_path, result):
        if self.verbose:
            self.report_change('new result:', proj, sarif_path, result)
        self.add_stat('ADDED', proj, sarif_path, result)

    def on_removed_result(self, proj, sarif_path, result):
        if self.verbose:
            self.report_change('result went away:', proj, sarif_path, result)
        self.add_stat('REMOVED', proj, sarif_path, result)

    def on_unchanged_result(self, proj, sarif_path, old_result, new_result):
        if self.verbose:
            self.report_change('unchanged result:', proj, sarif_path, new_result)
        self.add_stat('UNCHANGED', proj, sarif_path, old_result)

    def report_change(self, title, proj, sarif_path, result):
        if self.filter_rule:
            if not self.filter_rule(result):
                return
        heading = title.upper()
        heading += ' %s:' % self.classifier.classify(proj, sarif_path, result)
        if 'ruleId' in result:
            heading += ' %s:' % result['ruleId']
        print('-' * 76)
        print(heading)
        print('-' * 76)
        print(get_comparable_result(result, sarif_path.parent))

    def add_stat(self, event, proj, sarif_path, result):
        if self.filter_rule:
            if not self.filter_rule(result):
                return
        ruleId = result.get('ruleId', '')
        kind = self.classifier.classify(proj, sarif_path, result)
        self.rating_changes.on_event(event, kind)
        self.add(ruleId, kind, proj, event)

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

    def filter_rule(result):
        if args.rule_id:
            ruleId = result.get('ruleId', '')
            if ruleId != args.rule_id:
                return False;
        return True

    comparison = Comparison(config,
                            verbose=args.verbose,
                            filter_rule=filter_rule)

    for proj in projects:
        before = ProjectBuild(proj, Path(config.before_build_dir, proj.name))
        after  = ProjectBuild(proj, Path(config.after_build_dir, proj.name))
        before_sarif_paths = before.get_rel_sarif_paths()
        after_sarif_paths = after.get_rel_sarif_paths()
        all_sarif_paths = set()
        all_sarif_paths |= before_sarif_paths
        all_sarif_paths |= after_sarif_paths
        for rel_sarif_path in sorted(all_sarif_paths):
            if rel_sarif_path in before_sarif_paths:
                before_results, before_result_dict = before.get_comparable_results(rel_sarif_path)
            else:
                # A new sarif file appeared
                before_results, before_result_dict = set(), dict()
                comparison.on_new_sarif_file(proj, rel_sarif_path)

            if rel_sarif_path in after_sarif_paths:
                after_results, after_result_dict = after.get_comparable_results(rel_sarif_path)
            else:
                # An existing sarif file went away
                after_results, after_result_dict = set(), dict()
                comparison.on_removed_sarif_file(proj, rel_sarif_path)

            all_results = set()
            all_results |= before_results
            all_results |= after_results
            for str_result in sorted(all_results):
                if str_result not in before_results:
                    result = after_result_dict[str_result]
                    comparison.on_new_result(proj,
                                             after.get_path(rel_sarif_path),
                                             result)
                elif str_result not in after_results:
                    result = before_result_dict[str_result]
                    comparison.on_removed_result(proj,
                                                 before.get_path(rel_sarif_path),
                                                 result)
                else:
                    old_result = before_result_dict[str_result]
                    new_result = after_result_dict[str_result]
                    comparison.on_unchanged_result(proj,
                                                   after.get_path(rel_sarif_path),
                                                   old_result, new_result)
    comparison.print_item(0)

    if comparison.new_sarif_files:
        print(f'New .sarif files: {len(comparison.new_sarif_files)}')
        for proj_name, rel_sarif_path in sorted(comparison.new_sarif_files):
            print(f'  {proj_name}: {rel_sarif_path}')
    if comparison.removed_sarif_files:
        print(f'Removed .sarif files: {len(comparison.removed_sarif_files)}')
        for proj_name, rel_sarif_path in sorted(comparison.removed_sarif_files):
            print(f'  {proj_name}: {rel_sarif_path}')

if __name__ == '__main__':
    main()
