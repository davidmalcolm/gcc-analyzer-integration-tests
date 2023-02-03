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
import json
import logging
from pathlib import Path
import subprocess
import sys
import threading

import jsonschema
#import sarif
import sarif.loader

from projects import get_projects

############################################################################

class Compiler:
    pass

class GCC(Compiler):
    def __init__(self, install_bin_path):
        self.install_bin_path = install_bin_path
        self.c_compiler_path = Path(install_bin_path, 'gcc')
        self.cplusplus_compiler_path = Path(install_bin_path, 'g++')

    def verify(self):
        logging.info('Getting toolchain version')
        subprocess.run([self.c_compiler_path, '--version'], check=True)
        subprocess.run([self.cplusplus_compiler_path, '--version'], check=True)

############################################################################
# Logic for running tests
############################################################################

class Config:
    def __init__(self, abs_src_dir, toolchain, downloads_dir, run_dir, sarif_schema_path):
        self.abs_src_dir = abs_src_dir
        self.toolchain = toolchain
        self.downloads_dir = downloads_dir
        self.run_dir = run_dir
        with Path(sarif_schema_path).open() as f:
            self.sarif_schema = json.load(f)
        self.num_processors = self.count_num_processors()

    def get_make_jobs_arg(self):
        if self.num_processors > 0:
            return '-j%i' % self.num_processors
        else:
            return ''

    def count_num_processors(self):
        result = 0
        with open('/proc/cpuinfo') as f:
            for line in f.readlines():
                if 'processor' in line:
                    result += 1
        return result

def build_project(config, proj):
    # Make a project directory within the run directory
    proj_dir = Path(config.run_dir, proj.name)
    proj_dir.mkdir(exist_ok=True)

    # Extract and prepare source tree:
    proj.prep(config, proj_dir)

    # configure&build
    proj.build(config, proj_dir)

    proj.verify(config, proj_dir)

    # scrape out the results
    results = []
    for sarif_path in Path(proj_dir).glob('**/*.sarif'):
        if sarif_path.name == 'manifest.sarif':
            continue
        # Validate against the schema
        logging.info('Validating %s' % sarif_path)
        with sarif_path.open() as f:
            instance = json.load(f)
        jsonschema.validate(instance, schema=config.sarif_schema)

        results.append(sarif.loader.load_sarif_file(sarif_path))

    return results

def print_result(result):
    #print(result)
    for sarif_file in result:
        print(sarif_file)
        #print(sarif_file.json)
    # TODO

def main():
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)
    logging.info('Started')

    parser = argparse.ArgumentParser(
        prog = 'ProgramName',
        description = 'What the program does',
        epilog = 'Text at the bottom of help')
    parser.add_argument('--gcc-bin-path', type=Path, required=True)
    parser.add_argument('--downloads-dir', type=Path, required=True)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--sarif-schema-path', type=Path, required=True)
    parser.add_argument('--projects', required=False, nargs="+", metavar='PROJNAME',
                        help="If provided, restrict to just the named project(s)")
    args = parser.parse_args()
    logging.info('gcc_bin_path: %s' % args.gcc_bin_path)
    logging.info('downloads_dir: %s' % args.downloads_dir)
    logging.info('run_dir: %s' % args.run_dir)
    logging.info('sarif_schema_path: %s' % args.sarif_schema_path)

    toolchain = GCC(args.gcc_bin_path)
    toolchain.verify()

    abs_src_dir = Path(sys.argv[0]).parent.absolute()

    config = Config(abs_src_dir,
                    toolchain,
                    args.downloads_dir,
                    args.run_dir,
                    args.sarif_schema_path)

    config.run_dir.mkdir(exist_ok=True)

    projects = get_projects(args.projects)

    logging.info('projects: %s' % [proj.name for proj in projects])

    if len(projects) > 1:
        # Build the projects in parallel
        threads = []
        for proj in projects:
            thread = threading.Thread(target=build_project, args=(config, proj))
            thread.start()
            logging.info('Started thread %r: %s' % (thread, proj.name))
            threads.append((thread, proj))
        for thread, proj in threads:
            thread.join()
            logging.info('Joined thread %r: %s' % (thread, proj.name))
    else:
        # Build the projects serially
        for proj in projects:
            result = build_project(config, proj)
            print_result(result)

    logging.info('Finished')

if __name__ == '__main__':
    main()
