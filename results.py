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

import io
from pathlib import Path
from pprint import pprint
import json
import re
import sys

from sarif.sarif_file import SarifFile

# FIXME:
sys.path.append('../sarif-dump')
from sarifdump import GccStyleDumper

############################################################################

# Warning classifications
#
# "GOOD" vs "BAD" refers to how well the analyzer is doing, rather than
# how well the projects being analyzed are doing e.g. a true positive is
# 'GOOD'.

GOOD_KINDS = {'TRUE',  # a true positive
              'EMBARGOED'} # a true positive that can't be shared publicly yet

BAD_KINDS = {'GCCBZ', # a false positive that has an associated report in GCC's bugzilla
             'FALSE', # a false positive that isn't in GCC's bugzilla
             'UNKNOWN', # a diagnostic we don't know how to classify
             'TODO', # a diagnostic that we've seen but haven't yet classified further
             'FAILURE' } # a crash of the analyzer

class Ratings:
    """
    Stats about how well a particular set of stats did.
    """
    def __init__(self):
        self.stats_by_kind = {}
        self.good = 0
        self.bad = 0
        self.total = 0

    def on_kind(self, kind, count = 1):
        if kind in self.stats_by_kind:
            self.stats_by_kind[kind] += count
        else:
            self.stats_by_kind[kind] = count
        if kind in GOOD_KINDS:
            self.good += count
        elif kind in BAD_KINDS:
            self.bad += count
        else:
            raise ValueError('unknown kind: %s' % kind)
        self.total += count

    def get_score(self) -> float:
        if self.total > 0:
            return self.good / self.total
        else:
            return 0.0

############################################################################

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
                m = re.match('^GCCBZ: (.+)$', line)
                if m:
                    self.add_rule('GCCBZ', m.group(1))
                    continue
                m = re.match('^FALSE: (.+)$', line)
                if m:
                    self.add_rule('FALSE', m.group(1))
                    continue
                m = re.match('^EMBARGOED: (.+)$', line)
                if m:
                    self.add_rule('EMBARGOED', m.group(1))
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

class JulietClassifier:
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

def get_classifier(path):
    if path.name == 'Juliet.txt':
        return JulietClassifier()
    elif path:
        return ClassificationFile(path)
    else:
        return None

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

PROFILE_FIELDS = ['user', 'sys', 'wall', 'ggc_mem']

class InvocationProfile:
    def __init__(self, json_obj, rel_sarif_path):
        #print(json_obj) # TODO
        self.json_obj = json_obj
        self.rel_sarif_path = rel_sarif_path
        self.timevars = self.json_obj['timevars']
        total = self.timevars[-1]
        assert total['name'] == 'TOTAL'
        self.total = total['elapsed']
        self.analyzer_total = dict([(field, 0) for field in PROFILE_FIELDS])
        for tv in self.timevars:
            if tv['name'].startswith('analyzer'):
                for field in PROFILE_FIELDS:
                    self.analyzer_total[field] += tv['elapsed'][field]

    def get_proportion(self, field) -> float:
        """
        Get the fraction of the total elapsed for FIELD taken up by
        analyzer-related timevars.
        """
        if self.total[field] == 0:
            return 0.0
        else:
            return float(self.analyzer_total[field]) / float(self.total[field])

    def get_without_analysis(self) -> float:
        """
        Get number of user seconds that would have been spent if -fanalyzer
        wasn't enabled.
        """
        total = float(self.total['user'])
        analyzer = float(self.analyzer_total['user'])
        return total - analyzer

    def get_slowdown(self) -> float:
        total = float(self.total['user'])
        analyzer = float(self.analyzer_total['user'])
        without_analyzer = total - analyzer
        if without_analyzer != 0:
            return total / without_analyzer
        else:
            return 0

    def get_greatest_analyzer_item(self) -> (str, float):
        name = None
        amt = 0.0
        for tv in self.timevars:
            prefix = 'analyzer: '
            if tv['name'].startswith(prefix):
                if tv['elapsed']['user'] > amt:
                    amt = float(tv['elapsed']['user'])
                    name = tv['name'][len(prefix):]
        return (name, amt)

    def report(self) -> str:
        """
        Generate a string that emulates the output of GCC's -ftime-report.
        """
        result = f"{'Time variable':35}{'usr':>16}{'sys':>14}{'wall':>14}{'GGC':>16}\n"
        for tv in self.timevars:
            result += f"{tv['name']:35}:"
            elapsed = tv['elapsed']
            for field in PROFILE_FIELDS:
                if self.total[field] == 0:
                    percent = 0.0
                else:
                    percent = (float(elapsed[field]) / self.total[field]) * 100.0
                if field == 'ggc_mem':
                    result += f"{elapsed[field]:7} ({percent:3.0f}%)"
                    # TODO: show size amount: scale and label
                else:
                    result += f"{float(elapsed[field]):7.2f} ({percent:3.0f}%)"
            result += "\n"
        return result

def get_comparable_results(base_sarif_path, rel_sarif_path):
    """
    Load a .sarif file found at rel_sarif_path below base_sarif_path.
    Return a (set, dict, failures, profiles) 4-tuple where:
    - the set is a set of strings containing stringified versions
    of the results (with the paths expressed as they were in the sarif file,
    to help comparisons)
    - the dict is a mapping from the above strings to sarif result objects
    - failures is a set of failures (if any)
    - profiles is a list of InvocationProfile objects
    """
    str_results = []
    d = {}
    failures = set()
    profiles = []

    sarif_path = Path(base_sarif_path, rel_sarif_path)
    #base_src_path = sarif_path.parent
    try:
        with open(sarif_path, encoding="utf-8") as file_in:
            data = json.load(file_in)
        sarif_file =  SarifFile(sarif_path, data)
    except json.decoder.JSONDecodeError as err:
        failures.add('json.decoder.JSONDecodeError: %s' % err)
        return set(str_results), d, failures, profiles
    for result in sarif_file.get_results():
        s = get_comparable_result(result, '')
        str_results.append(s)
        d[s] = result

    run_data = sarif_file.runs[0].run_data
    invocations = run_data.get('invocations', None)
    if invocations:
        for invocation in invocations:
            for notification in invocation['toolExecutionNotifications']:
                if notification['level'] == 'error':
                    with io.StringIO() as f:
                        dumper = GccStyleDumper(f, '')
                        dumper.dump_sarif_notification(notification)
                        v = f.getvalue()
                        failures.add(f.getvalue())
            properties = invocation.get('properties', None)
            if properties:
                time_report = properties.get('gcc/timeReport', None)
                if time_report:
                    profiles.append(InvocationProfile(time_report, rel_sarif_path))
    return set(str_results), d, failures, profiles

def get_path_length(result):
    if 'codeFlows' not in result:
        return None
    code_flow = result['codeFlows'][0]
    thread_flow = code_flow['threadFlows'][0]
    return len(thread_flow['locations'])

class ProjectBuild:
    """
    A particular build of a particular project.
    """
    def __init__(self, project, proj_build_dir):
        self.project = project
        self.proj_build_dir = proj_build_dir

    def get_rel_sarif_paths(self):
        """
        Get a set of all .sarif files below the project build dir,
        as paths expressed relative to it.
        """
        return get_sarif_paths(self.proj_build_dir)

    def get_comparable_results(self, rel_sarif_path):
        """
        Load a .sarif file found at rel_sarif_path below self.proj_build_dir.
        Return a (set, dict, failures, profiles) 4-tuple where:
        - the set is a set of strings containing stringified versions
        of the results (with the paths expressed as they were in the sarif file,
        to help comparisons)
        - the dict is a mapping from the above strings to sarif result objects
        - failures is a set of failures (if any)
        - profiles is a list of InvocationProfile objects
        """
        return get_comparable_results(self.proj_build_dir, rel_sarif_path)

    def get_path(self, rel_path):
        """
        Given a path relative to the top-level build directory for this project,
        convert to a path that includes self.proj_build_dir.
        """
        return Path(self.proj_build_dir, rel_path)
