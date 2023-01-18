Test harness for GCC's -fanalyzer
=================================

This is an integration test suite for
`GCC's -fanalyzer option <https://gcc.gnu.org/wiki/StaticAnalyzer>`_.

The idea is to build various C projects using a candidate installation of GCC
with ``-fanalyzer``, and capture the diagnostics in
`SARIF <https://sarifweb.azurewebsites.net/>`_ format.

This way, the diagnostics emitted by different GCC builds can be compared
i.e. the projects being built are fixed; it's the GCC version that varies.

The harness assumes the GCC being tested implements
``-fdiagnostics-format=sarif-file`` (added in GCC version 13).


Goals
*****

* integration testing of ``-fanalyzer`` on real-world C projects

  * signal:noise ratio

* exercise ``-fanalyzer`` on code written in a variety of different
  styles, by different teams, using each upstream's default choice of
  compilation flags.


Non-goals
*********

* unit-testing of specific code constructs (this belongs in GCC's own
  test suite)

* C++ (for now)


Current projects tested
=======================

See `test.py` for the full details

* apr-1.7.0
* coreutils-9.1
* Doom
* git-2.39.0
* haproxy-2.7.1
* ImageMagick-7.1.0-57
* Juliet-1.3 (a test suite for static analysis tools)
* linux-5.10.162 (with ``allnoconfig``; currently without gathering
  SARIF files)
* pcre2-10.42
* qemu-7.2.0
* xz-5.4.0
* zlib-1.2.13


Prerequisites
*************

TODO

$ sudo pip install sarif-tools

TODO: is this in Fedora yet?


Usage
*****

TODO

