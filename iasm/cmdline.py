from . import __version__, __doc__, _author, _license, _url, _license_disclaimer
from .arch import _supported_archs, _supported_modes
import argparse
import sys

from pygments.styles import get_all_styles


class _Print(argparse.Action):
    r'''Print a given message bypassing the formatting rules of
        argparse, then, exit.'''
    def __init__(self, *args, **kargs):
        self.message = kargs.pop('message')
        argparse.Action.__init__(self, *args, **kargs)

    def __call__(self, parser, namespace, values, option_string=None):
        parser.exit(message=self.message)


def build_argparser():
    python_version = sys.version.split(' ', 1)[0]
    parser = argparse.ArgumentParser(
        fromfile_prefix_chars='@', description=__doc__
    )

    parser.add_argument(
        "-a",
        "--arch",
        "--architecture",
        metavar='<arch>',
        dest='arch',
        required=True,
        help='select the CPU architecture.',
        choices=_supported_archs.keys()
    )

    parser.add_argument(
        "-m",
        "--mode",
        metavar='<mode>',
        dest='mode',
        required=True,
        help='select the CPU mode.',
        choices=_supported_modes.keys()
    )

    parser.add_argument(
        "--code-size",
        metavar='<sz>',
        dest='code_sz',
        required=False,
        default=2 * 1024 * 1024,
        help='memory allocated for code.'
    )

    parser.add_argument(
        "--style",
        metavar='<style>',
        dest='style',
        required=False,
        default='paraiso-dark',
        help='style for the prompt.',
        choices=list(sorted(get_all_styles()))
    )

    parser.add_argument(
        "-r",
        "--reg-glob",
        metavar='<glob>',
        dest='reg_globs',
        required=False,
        action='append',
        help=
        'add one or more glob expressions to show a subset of the registers, like "e?x eip" (x86) or "r*" (arm).'
    )

    parser.add_argument(
        '-V',
        '--version',
        nargs=0,
        action=_Print,
        message='{prog} {version} (Python {python_version}) - {license}\n\n{doc}'
        '\n\n{license_disclaimer}'.format(
            prog=parser.prog,
            doc=__doc__,
            version=__version__,
            python_version=python_version,
            license=_license,
            license_disclaimer=_license_disclaimer.format(
                author=_author, url=_url
            )
        ),
        help='show %(prog)s\'s version and license, then exit'
    )

    return parser
