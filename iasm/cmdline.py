from . import __version__, __doc__, _author, _license, _url, _license_disclaimer
from .arch import _supported_archs, _supported_modes
import argparse
import sys
import unicorn
import keystone

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
    keystone_version = '.'.join(str(i) for i in keystone.version_bind())
    unicorn_version = '.'.join(str(i) for i in unicorn.version_bind())

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
        type=int,
        default=2 * 1024 * 1024,
        help='memory allocated for code.'
    )

    parser.add_argument(
        "--program-counter",
        metavar='<pc>',
        dest='pc_addr',
        required=False,
        type=int,
        default=0x1000000,
        help='starting program counter address.'
    )

    parser.add_argument(
        "--style",
        metavar='<style>',
        dest='style',
        required=False,
        default='paraiso-dark',
        help='style for the prompt.',
        choices=sorted(list(get_all_styles()) + ['none'])
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
        "-i",
        "--init",
        metavar='<file>',
        dest='init_file',
        required=False,
        help=
        'execute the instructions from the given file before starting the interactive session.'
    )

    parser.add_argument(
        "--show-regs",
        action='store_true',
        dest='show_regs',
        required=False,
        help=
        'show the registers available for the given architecture/mode and quit.'
    )

    parser.add_argument(
        "--timeout",
        metavar='<secs>',
        dest='timeout',
        type=float,
        required=False,
        default=5,
        help='timeout for parsing and executing each assembly instruction.'
    )

    parser.add_argument(
        "-v",
        metavar='<version>',
        dest='isa_version',
        required=False,
        default='latest',
        help='version of the ISA.'
    )

    parser.add_argument(
        "--simple-prompt",
        action='store_true',
        dest='simple_prompt',
        required=False,
        default=False,
        help='simpler alternative prompt.'
    )

    parser.add_argument(
        "--no-history",
        action='store_true',
        required=False,
        default=False,
        help='disable shell history of the commands.'
    )

    parser.add_argument(
        '-V',
        '--version',
        nargs=0,
        action=_Print,
        message=
        '{prog} {version} (Python {python_version}, Keystone {keystone_version}, Unicorn {unicorn_version}) - {license}\n\n{doc}'
        '\n\n{license_disclaimer}'.format(
            prog=parser.prog,
            doc=__doc__,
            version=__version__,
            python_version=python_version,
            keystone_version=keystone_version,
            unicorn_version=unicorn_version,
            license=_license,
            license_disclaimer=_license_disclaimer.format(
                author=_author, url=_url
            )
        ),
        help='show %(prog)s\'s version and license, then exit'
    )

    return parser
