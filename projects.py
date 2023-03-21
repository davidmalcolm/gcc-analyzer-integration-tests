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

from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import logging
import os
from pathlib import Path, PurePath
import subprocess
from urllib.parse import urlparse

from results import ClassificationFile, JulietClassifier

############################################################################
# Various support classes
############################################################################

class SourceArchive:
    def __init__(self, url, hexdigest, alg='sha256'):
        self.url = url
        self.hexdigest = hexdigest
        self.alg = alg

    @property
    def filename(self):
        return PurePath(urlparse(self.url).path).name

    def get_cached_file_path(self, downloads_dir):
        return Path(downloads_dir, self.filename)

    def ensure_cached(self, downloads_dir):
        Path(downloads_dir).mkdir(exist_ok=True)
        cached_file_path = self.get_cached_file_path(downloads_dir)
        if os.path.exists(cached_file_path):
            logging.info('Using cached %s', cached_file_path)
        else:
            logging.info('Downloading %s to %s',
                         self.url, cached_file_path)
            subprocess.run(['wget', self.url, '--continue'],
                           cwd=downloads_dir,
                           check=True)
            logging.info('Finished downloading %s to %s',
                         self.url, cached_file_path)
        with cached_file_path.open(mode='rb') as f:
            content = f.read()
        h = hashlib.new(self.alg)
        h.update(content)
        actual_digest = h.hexdigest()
        expected_digest = self.hexdigest
        if actual_digest != expected_digest:
            raise ValueError('digest %r != expected %r'
                             % (actual_digest, expected_digest))

    def extract_to(self, config, dst_path):
        raise NotImplementedError()

class Tarball(SourceArchive):
    def extract_to(self, config, dst_path):
        self.ensure_cached(config.downloads_dir)
        cached_file_path = self.get_cached_file_path(config.downloads_dir)
        logging.info('Unpacking %s to %s', cached_file_path, dst_path)
        subprocess.run(['tar', '--extract',
                        '--file', cached_file_path.absolute()],
                       cwd=dst_path,
                       check=True)
        logging.info('Finished unpacking %s to %s', cached_file_path, dst_path)

class Zipfile(SourceArchive):
    def extract_to(self, config, dst_path):
        self.ensure_cached(config.downloads_dir)
        cached_file_path = self.get_cached_file_path(config.downloads_dir)
        logging.info('Unpacking %s to %s', cached_file_path, dst_path)
        subprocess.run(['unzip',
                        '-q', # Suppress printing of filenames, as this can be very slow
                        '-o', # FIXME
                        cached_file_path.absolute()],
                       cwd=dst_path,
                       check=True)
        logging.info('Finished unpacking %s to %s', cached_file_path, dst_path)

class SarifFile:
    def __init__(self, path):
        self.path = path
        with path.open() as f:
            self.json = json.load(f)

    def __repr__(self):
        return 'SarifFile(%r)' % self.path

def remove_text(path, text):
    """FIXME"""
    with path.open('r') as f_in:
        old = f_in.read()
    new = old.replace(text, '')
    if new != old:
        with path.open('w') as f_out:
            f_out.write(new)

def remove_line(path, text):
    """FIXME"""
    remove_text(path, text + '\n')

def fixup_file(path, old_text, new_text):
    """FIXME"""
    with path.open('r') as f_in:
        old = f_in.read()
    new = old.replace(old_text, new_text)
    if new != old:
        with path.open('w') as f_out:
            f_out.write(new)

############################################################################

class TestProject:
    """
    Base class for projects.
    Responsibilities include:
    - how to build whilst:
      - using a custom toolchain
      - injecting "-fanalyzer -fdiagnostics-format=sarif-file" into flags
    """
    def __init__(self, name):
        self.name = name

    def prep(self, config, proj_dir):
        logging.info('Preparing %s', self.name)
        self.src.extract_to(config, proj_dir)

    def configure(self, toolchain, proj_dir):
        logging.info('Configuring %s', self.name)
        subprocess.run(['./configure',
                        'CC=%s' % toolchain.c_compiler_path,
                        'CFLAGS=-fanalyzer -fdiagnostics-format=sarif-file'],
                       cwd=Path(proj_dir, self.name),
                       check=True)
        logging.info('Finished configuring %s', self.name)

    def configure_meson(self, toolchain, proj_dir):
        logging.info('Configuring %s', self.name)
        subprocess.run(['./configure',
                        '--cc=%s' % toolchain.c_compiler_path,
                        '--extra-cflags=-fanalyzer -fdiagnostics-format=sarif-file'],
                       cwd=Path(proj_dir, self.name),
                       check=True)
        logging.info('Finished configuring %s', self.name)

    def make(self, config, proj_dir, extra_args=None, check=True):
        logging.info('Invoking "make" on %s', self.name)
        args = ['make', config.get_make_jobs_arg()]
        if extra_args:
            args += extra_args
        if not check:
            args.append('-k')
        args.append('V=1')
        cwd=Path(proj_dir, self.name)
        logging.info('cwd: %s' % cwd)
        logging.info('args: %s' % ' '.join(args))
        subprocess.run(args,
                       cwd=cwd,
                       check=check)
        logging.info('Finished invoking "make" on %s', self.name)

    def verify(self, config, proj_dir):
        raise NotImplementedError()

    def verify_file_exists(self, within_dir, expected_file):
        path = Path(within_dir, expected_file)
        if path.exists():
            logging.info('OK: expected file %s exists' % expected_file)
        else:
            logging.error('ERR: expected file %s does not exist (%r)'
                          % (expected_file, path))
            raise ValueError('missing file: %s (not found within %s)' % (expected_file, path))

    def verify_sarif_files_exist(self, within_dir, expected_sarif_files):
        missing = []
        for expected_file in expected_sarif_files:
            path = Path(within_dir, expected_file)
            if path.exists():
                logging.info('OK: expected SARIF file %s exists' % expected_file)
            else:
                logging.error('ERR: expected SARIF file %s does not exist (%r)'
                              % (expected_file, path))
                missing.append(expected_file)
        if missing:
            raise ValueError('missing SARIF files: %s' % missing)

    def verify_sarif_file_exists(self, within_dir, expected_sarif_file):
        self.verify_sarif_files_exist(within_dir, [expected_sarif_file])

    def build(self, config, proj_dir):
        """
        Default implementation of TestProject.build:
        run 'configure', then 'make'.
        """
        self.configure(config.toolchain, proj_dir)
        self.make(config, proj_dir)

    def get_classifier(self, config):
        path = Path(config.abs_src_dir, 'known-issues', self.name + '.txt')
        return ClassificationFile(path)

############################################################################
# Various specific projects
############################################################################

class Apr(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'apr-1.7.0')
        self.src = Tarball('https://dlcdn.apache.org//apr/apr-1.7.0.tar.gz',
                           '48e9dbf45ae3fdc7b491259ffb6ccf7d63049ffacbc1c0977cced095e4c2d5a2')

    def verify(self, config, proj_dir):
        expected_sarif_files = ['apr_hash.c.sarif']
        self.verify_sarif_files_exist(Path(proj_dir, self.name),
                                      expected_sarif_files)

class Coreutils(TestProject):
    # configure takes almost 2 minutes on my box
    def __init__(self):
        TestProject.__init__(self, 'coreutils-9.1')
        self.src = Tarball('https://ftp.gnu.org/gnu/coreutils/coreutils-9.1.tar.xz',
                           '61a1f410d78ba7e7f37a5a4f50e6d1320aca33375484a3255eddf17a38580423')

    def verify(self, config, proj_dir):
        expected_sarif_files = ['asnprintf.c.sarif', 'yes.c.sarif']
        self.verify_sarif_files_exist(Path(proj_dir, self.name),
                                      expected_sarif_files)

class Doom(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'doom')
        self.src = Zipfile('https://www.gamers.org/pub/idgames/source/doomsrc.zip',
                           '95ccda470805701b11bbc2657337faa3ff4a28c3a636f37c5a1440055f3e2d9b')

    def prep(self, config, proj_dir):
        TestProject.prep(self, config, proj_dir)
        subprocess.run(['tar', '--extract',
                        '--file', Path('linuxdoom-1.10.src.tgz')],
                       cwd=proj_dir,
                       check=True)
        remove_line(Path(proj_dir, 'linuxdoom-1.10/i_video.c'),
                    '#include <errnos.h>')

    def configure(self, toolchain, proj_dir):
        pass

    def make(self, config, proj_dir, extra_args=None, check=True):
        logging.info('Invoking "make" on %s', self.name)
        CFLAGS='-g -Wall -DNORMALUNIX -DLINUX' # from Makefile
        # Seems to be needed by m_misc.c:
        CFLAGS += ' -Wno-pointer-to-int-cast'

        # Inject analyzer and SARIF output:
        CFLAGS += ' -fanalyzer -fdiagnostics-format=sarif-file'

        args = ['make', config.get_make_jobs_arg(),
                'CC=%s' % config.toolchain.c_compiler_path,
                'CFLAGS=%s' % CFLAGS]
        if extra_args:
            args += extra_args
        subprocess.run(args,
                       cwd=Path(proj_dir, 'linuxdoom-1.10'),
                       check=False)
        # TODO: fix the build; currently failing in m_misc.c with various
        # errors of the form:
        #        m_misc.c:296:45: error: initializer element is not constant

        logging.info('Finished invoking "make" on %s', self.name)

    def verify(self, config, proj_dir):
        OBJS=('''
        doomdef.o doomstat.o dstrings.o i_system.o i_sound.o i_video.o
        i_net.o tables.o f_finale.o f_wipe.o d_main.o d_net.o d_items.o
        g_game.o
        m_menu.o m_misc.o m_argv.o m_bbox.o m_fixed.o m_swap.o m_cheat.o m_random.o
        am_map.o
        p_ceilng.o p_doors.o p_enemy.o p_floor.o p_inter.o p_lights.o p_map.o
        p_maputl.o p_plats.o p_pspr.o p_setup.o p_sight.o p_spec.o p_switch.o
        p_mobj.o p_telept.o p_tick.o p_saveg.o p_user.o
        r_bsp.o r_data.o r_draw.o r_main.o r_plane.o r_segs.o r_sky.o r_things.o
        w_wad.o wi_stuff.o v_video.o st_lib.o st_stuff.o hu_stuff.o hu_lib.o s_sound.o z_zone.o info.o sounds.o
        ''')
        expected_sarif_files = [obj.replace('.o', '.c.sarif')
                                for obj in OBJS.split()]
        self.verify_sarif_files_exist(Path(proj_dir, 'linuxdoom-1.10'),
                                      expected_sarif_files)

class Git(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'git-2.39.0')
        self.src = Tarball('https://mirrors.edge.kernel.org/pub/software/scm/git/git-2.39.0.tar.xz',
                           'ba199b13fb5a99ca3dec917b0bd736bc0eb5a9df87737d435eddfdf10d69265b')

    def verify(self, config, proj_dir):
        expected_sarif_files = ['usage.c.sarif']
        self.verify_sarif_files_exist(Path(proj_dir, self.name),
                                      expected_sarif_files)

class GnuTLS(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'gnutls-3.7.8')
        self.src = Tarball('https://www.gnupg.org/ftp/gcrypt/gnutls/v3.7/gnutls-3.7.8.tar.xz',
                           'c58ad39af0670efe6a8aee5e3a8b2331a1200418b64b7c51977fb396d4617114')

class HAProxy(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'haproxy-2.7.1')
        self.src = Tarball('https://www.haproxy.org/download/2.7/src/haproxy-2.7.1.tar.gz',
                           '155f3a2fb6dfc1fdfd13d946a260ab8dd2a137714acb818510749e3ffb6b351d')

    def prep(self, config, proj_dir):
        TestProject.prep(self, config, proj_dir)
        # Remove "-Wno-string-plus-int -Wno-atomic-alignment" from build flags.
        # This is a workaround for https://github.com/microsoft/sarif-tools/issues/12
        src_dir = Path(proj_dir, self.name)
        remove_line(Path(src_dir, 'Makefile'),
                    'SPEC_CFLAGS += $(call cc-nowarn,string-plus-int)')
        remove_line(Path(src_dir, 'Makefile'),
                    'SPEC_CFLAGS += $(call cc-nowarn,atomic-alignment)')

    def build(self, config, proj_dir):
        self.make(config,
                  proj_dir,
                  extra_args=['TARGET=linux-glibc',
                              'USE_OPENSSL=1',
                              'CC=%s' % config.toolchain.c_compiler_path,
                              'DEBUG_CFLAGS=-fanalyzer -fdiagnostics-format=sarif-file'],
                  # TODO: get it to succeed:
                  check=False)

    def verify(self, config, proj_dir):
        expected_sarif_files = ['acl.c.sarif', 'xprt_handshake.c.sarif']
        self.verify_sarif_files_exist(Path(proj_dir, self.name),
                                      expected_sarif_files)

class Httpd(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'httpd-2.4.54')
        self.src = Tarball('https://dlcdn.apache.org/httpd/httpd-2.4.54.tar.bz2',
                           'eb397feeefccaf254f8d45de3768d9d68e8e73851c49afd5b7176d1ecf80c340')

class ImageMagick(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'ImageMagick-7.1.0-57')
        self.src = Tarball('https://imagemagick.org/archive/ImageMagick-7.1.0-57.tar.xz',
                           '9c3bc3de37376b90a643b9437435cb477db68596b26a778a584020915196870b')

    def verify(self, config, proj_dir):
        self.verify_sarif_file_exists(Path(proj_dir, self.name),
                                      'magick.c.sarif')

class Juliet(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'Juliet')
        self.src = Zipfile('https://samate.nist.gov/SARD/downloads/test-suites/2022-08-11-juliet-c-cplusplus-v1-3-1-with-extra-support.zip',
                           '331b288f17ea95076d76e7bcc1d0e307f9e78241b16e744340213c8e2986919a')

    def prep(self, config, proj_dir):
        TestProject.prep(self, config, proj_dir)
        # TODO: fixup
        test_case_dir = sorted([p for p in proj_dir.iterdir() if p.is_dir()])
        logging.info('Fixing up SRCS within %s Makefiles' % len(test_case_dir))
        # FIXME: might want a thread pool for this eventually
        for test_case_dir in test_case_dir:
            fixup_file(Path(test_case_dir, 'Makefile'),
                       'SRCS := $(shell find $(SRC) -name *.cpp -or -name *.c* -or -name *.cc)',
                       'SRCS := $(shell find $(SRC) -name *.cpp -or -name *.c -or -name *.cc)')
        logging.info('Finished fixing up SRCS')

    def build(self, config, proj_dir):
        logging.info('Building Juliet')
        test_case_dir = sorted([p for p in proj_dir.iterdir() if p.is_dir()])
        executor = ProcessPoolExecutor(max_workers=config.num_processors)
        for test_case_dir in test_case_dir:
            # FIXME: while implementing, restrict to just:
            #   240071-v2.0.0/src/testcases/CWE415_Double_Free/s01/
            # print(test_case_dir.name)
            #if test_case_dir.name != '240071-v2.0.0':
            #    continue
            #self.build_test_case(config, test_case_dir)
            executor.submit(self.build_test_case, config, test_case_dir)
        logging.info('Finished building Juliet')

    def build_test_case(self, config, test_case_dir):
        logging.info('Building %s' % test_case_dir)

        CFLAGS = self.get_make_var(config, 'CFLAGS', test_case_dir)
        logging.info('CFLAGS from Makefile: %r' % CFLAGS)

        #CFLAGS += ' -c'

        # Inject analyzer and SARIF output:
        CFLAGS += ' -fanalyzer -fdiagnostics-format=sarif-file'

        CC_from_makefile = self.get_make_var(config, 'CC', test_case_dir)
        if CC_from_makefile == 'gcc':
            CC_to_use = config.toolchain.c_compiler_path
        elif CC_from_makefile == 'g++':
            CC_to_use = config.toolchain.cplusplus_compiler_path
            # Within 103336-v1.0.0's CWE440_Expected_Behavior_Violation/ we
            # get this failure when g++ defaults to C++17 (as of GCC 11):
            #   CWE440_Expected_Behavior_Violation__exception_01.cpp: At global scope:
            #   CWE440_Expected_Behavior_Violation__exception_01.cpp:30:21: error: ISO C++17 does not allow dynamic exception specifications
            #      30 | static void good1() throw (range_error) /* FIX: Declare that function throws an  exception */
            #         |                     ^~~~~
            # Work around this by injecting "-std=c++14"
            CFLAGS += ' -std=c++14'
        elif CC_from_makefile == 'cl':
            logging.info('CC in Makefile is "cl"; assuming Windows-specific test; skipping')
            return
        else:
            raise ValueError('unexpected value of CC in %s: %r'
                             % (Path(test_case_dir, 'Makefile'), CC_from_makefile))

        logging.info('CFLAGS to use: %r' % CFLAGS)

        args = ['make',
                'build',
                config.get_make_jobs_arg(),
                'CFLAGS=%s' % CFLAGS,
                'CC=%s' % CC_to_use,
                'V=1'
                ]
        subprocess.run(args,
                       cwd=test_case_dir,
                       check=True)
        logging.info('Finished invoking "make"')
        logging.info('Finished building %s' % test_case_dir)

    def get_make_var(self, config, var_name, dir_):
        args = ['make',
                '-f', Path(config.abs_src_dir, 'print-var.mak'),
                '-f', 'Makefile',
                'print-%s' % var_name]
        p = subprocess.run(args,
                           cwd=dir_,
                           capture_output=True,
                           check=True)
        return p.stdout.decode('utf-8').strip()

    def verify(self, config, proj_dir):
        self.verify_sarif_file_exists(proj_dir,
                                      '240071-v2.0.0/CWE415_Double_Free__malloc_free_char_01.c.sarif')

    def get_classifier(self, config):
        return JulietClassifier()

class Kernel(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'linux-5.10.162')
        self.src = Tarball('https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.162.tar.xz',
                           '941c7ddd7c27f49b4491e1c8fbf1efedcbac50b48ed8836ec91091ead69723f820a61bfda795378dcc728a782d2206189903333e83e255b723eec01157bbb0bb',
                           alg='sha512')

    def build(self, config, proj_dir):
        self.make(config,
                  proj_dir,
                  extra_args=['allnoconfig', 'all',
                              'CC=%s' % config.toolchain.c_compiler_path,
                              'V=1',
                              'DEBUG_CFLAGS=-fanalyzer -fdiagnostics-format=sarif-file'])

    def verify(self, config, proj_dir):
        self.verify_file_exists(Path(proj_dir, self.name), 'vmlinux')

        expected_sarif_files = ['char_dev.c.sarif',
                                'filesystems.c.sarif',
                                'kfifo.c.sarif',
                                'printk.c.sarif',
                                'syscall.c.sarif']
        self.verify_sarif_files_exist(Path(proj_dir, self.name),
                                      expected_sarif_files)

class OpenSSL(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'openssl-3.0.7')
        self.src = Tarball('https://www.openssl.org/source/openssl-3.0.7.tar.gz',
                           '83049d042a260e696f62406ac5c08bf706fd84383f945cf21bd61e9ed95c396e')

    def configure(self, toolchain, proj_dir):
        logging.info('Configuring %s', self.name)
        subprocess.run(['./Configure',
                        'CC=%s' % toolchain.c_compiler_path,
                        'CFLAGS=-fanalyzer -fdiagnostics-format=sarif-file'],
                       cwd=Path(proj_dir, self.name),
                       check=True)
        logging.info('Finished configuring %s', self.name)

class Pcre(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'pcre2-10.42')
        self.src = Tarball('https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.42/pcre2-10.42.tar.bz2',
                           '8d36cd8cb6ea2a4c2bb358ff6411b0c788633a2a45dabbf1aeb4b701d1b5e840')

    def verify(self, config, proj_dir):
        self.verify_sarif_file_exists(Path(proj_dir, self.name),
                                      'pcre2grep-pcre2grep.c.sarif')

class Pixman(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'pixman-0.42.2')
        self.src = Tarball('https://www.cairographics.org/releases/pixman-0.42.2.tar.gz',
                           '0a4e327aef89c25f8cb474fbd01de834fd2a1b13fdf7db11ab72072082e45881cd16060673b59d02054b1711ae69c6e2395f6ae9214225ee7153939efcd2fa5d',
                           alg='sha512')

class Qemu(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'qemu-7.2.0')
        self.src = Tarball('https://download.qemu.org/qemu-7.2.0.tar.xz',
                           '5b49ce2687744dad494ae90a898c52204a3406e84d072482a1e1be854eeb2157')

    def build(self, config, proj_dir):
        self.configure_meson(config.toolchain, proj_dir)
        self.make(config,
                  proj_dir,
                  # TODO: get it to succeed:
                  check=False)

    def verify(self, config, proj_dir):
        expected_sarif_files = ['build/main.c.c.sarif', 'build/cpu.c.c.sarif']
        self.verify_sarif_files_exist(Path(proj_dir, self.name),
                                      expected_sarif_files)

class Xz(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'xz-5.4.0')
        self.src = Tarball('https://www.tukaani.org/xz/xz-5.4.0.tar.xz',
                           '5f260e3b43f75cf43ca43d107dd18209f7d516782956a74ddd53288e02a83a31')

    def verify(self, config, proj_dir):
        self.verify_sarif_file_exists(Path(proj_dir, self.name),
                                      'src/xzdec/xzdec-xzdec.c.sarif')

class Zlib(TestProject):
    def __init__(self):
        TestProject.__init__(self, 'zlib-1.2.13')
        self.src = Tarball('https://www.zlib.net/zlib-1.2.13.tar.xz',
                           'd14c38e313afc35a9a8760dadf26042f51ea0f5d154b0630a31da0540107fb98')

    def configure(self, toolchain, proj_dir):
        logging.info('Configuring %s', self.name)
        subprocess.run(['./configure'],
                       cwd=Path(proj_dir, self.name),
                       check=True)
        logging.info('Finished configuring %s', self.name)

    def make(self, config, proj_dir, extra_args=None, check=True):
        logging.info('Invoking "make" on %s', self.name)
        args = ['make', config.get_make_jobs_arg()]
        if extra_args:
            args += extra_args
        args += ['CC=%s' % config.toolchain.c_compiler_path,
                 'CFLAGS=-O -fanalyzer -fdiagnostics-format=sarif-file']
        # ...but don't touch SFLAGS, to ensure that the link of the shared
        # library succeeds.
        subprocess.run(args,
                       cwd=Path(proj_dir, self.name),
                       check=check)
        logging.info('Finished invoking "make" on %s', self.name)

    def verify(self, config, proj_dir):
        expected_sarif_files = [
            # Via OBJZ:
            'adler32.c.sarif', 'crc32.c.sarif', 'deflate.c.sarif',
            'infback.c.sarif', 'inffast.c.sarif', 'inflate.c.sarif',
            'inftrees.c.sarif', 'trees.c.sarif', 'zutil.c.sarif',

            # Via OBJG:
            'compress.c.sarif', 'uncompr.c.sarif', 'gzclose.c.sarif',
            'gzlib.c.sarif', 'gzread.c.sarif', 'gzwrite.c.sarif'
        ]
        self.verify_sarif_files_exist(Path(proj_dir, self.name),
                                      expected_sarif_files)

def get_projects(names):
    """
    Get all projects with a name in names.
    If names is None then get all default projects.
    """
    default_projects = [
        Apr(),
        Coreutils(),
        Doom(),
        Git(),
        HAProxy(),
        ImageMagick(),
        Juliet(),
        Kernel(),
        Pcre(),
        Qemu(),
        Xz(),
        Zlib(),
    ]

    # TODO:
    failing_projects = [
        # doesn't yet configure: failing at "checking for NETTLE... no":
        GnuTLS(),

        # doesn't yet configure: needs APR installed:
        Httpd(),

        # Seems to get stuck on:
        #   crypto/ec/curve25519.c (twice); this is https://gcc.gnu.org/bugzilla/show_bug.cgi?id=107943
        #   providers/implementations/digests/blake2b_prov.c
        #   providers/implementations/digests/blake2s_prov.c
        # TODO: file bugs about this against analyzer
        OpenSSL(),

        # Seems to get stuck on pixman-sse2.c
        # TODO: file bug about this against analyzer
        Pixman(),
    ]

    if names:
        # Filter to the specified projects
        all_projects = default_projects + failing_projects
        all_project_names = set([project.name for project in all_projects])
        for arg in names:
            if arg not in all_project_names:
                logging.error('unrecognized project: %s' % arg)

        return [project
                for project in all_projects
                if project.name in names]
    else:
        return default_projects
