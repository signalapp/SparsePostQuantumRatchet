#! /usr/bin/env python3

import os
import argparse
import subprocess
import sys


def shell(command, expect=0, cwd=None, env={}):
    subprocess_stdout = subprocess.DEVNULL

    print("Env:", env)
    print("Command: ", end="")
    for i, word in enumerate(command):
        if i == 4:
            print("'{}' ".format(word), end="")
        else:
            print("{} ".format(word), end="")

    print("\nDirectory: {}".format(cwd))

    os_env = os.environ
    os_env.update(env)

    ret = subprocess.run(command, cwd=cwd, env=os_env)
    if ret.returncode != expect:
        raise Exception("Error {}. Expected {}.".format(ret, expect))


class extractAction(argparse.Action):

    def __call__(self, parser, args, values, option_string=None) -> None:
        # Extract spqr
        include_str = "-**::proto::** +:**::proto::**" 
        if args.include:
            include_str = "-** +:**::proto::** " + args.include
        if args.encoding:
            include_str = "-** +:**::proto::** +**::encoding::**"
        interface_include = "+**::proto::**"
        cargo_hax_into = [
            "cargo",
            "hax",
            "into",
            "-i",
            include_str,
            "fstar",
            "--z3rlimit",
            "300",
            "--interfaces",
            interface_include,
        ]
        hax_env = {}
        shell(
            cargo_hax_into,
            cwd=".",
            env=hax_env,
        )
        patch_extraction()
        return None


def patch_extraction():
    """Post-extraction fixups for bugs the F* sources and models cannot avoid.

    Keep every patch idempotent and assert that it applied, so a toolchain
    upgrade that changes the output fails loudly here instead of silently
    rotting.
    """
    spqr = os.path.join("proofs", "fstar", "extraction", "Spqr.fst")
    if not os.path.exists(spqr):
        # Partial extraction (e.g. `--encoding`) does not produce it.
        return

    # FIXME(FStarLang/FStar#4533): F* resolves `t_Error` in the selective
    # include `include Spqr.Bundle {t_Error as t_Error}` to the record of the
    # class `Core_models.Error.t_Error` and fails with
    #   Definition Spqr.Bundle._super_i0 cannot be found.
    # An abbreviation sidesteps the lookup; the enum's constructors are
    # re-exported on their own `include` lines.
    bad = "include Spqr.Bundle {t_Error as t_Error}"
    good = "unfold let t_Error = Spqr.Bundle.t_Error"
    with open(spqr) as f:
        src = f.read()
    if bad in src:
        with open(spqr, "w") as f:
            f.write(src.replace(bad, good, 1))
        print("patched: Spqr.fst t_Error re-export (_super_i0)")
    elif good not in src:
        raise Exception(
            "Spqr.fst has neither the buggy `{}` nor the patched `{}`. "
            "Check whether hax changed its output.".format(bad, good)
        )


class proveAction(argparse.Action):

    def __call__(self, parser, args, values, option_string=None) -> None:
        admit_env = {}
        if args.admit:
            admit_env = {"OTHERFLAGS": "--admit_smt_queries true"}
        shell(["make", "-C", "proofs/fstar/extraction/"], env=admit_env)
        return None


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="SPQR prove script. "
        + "Make sure to separate sub-command arguments with --."
    )
    subparsers = parser.add_subparsers()

    extract_parser = subparsers.add_parser(
        "extract", help="Extract the F* code for the proofs."
    )
    extract_parser.add_argument(
        "--include",
        required=False,
        help="Include flag to pass to hax.",
    )
    extract_parser.add_argument(
        "--encoding",
        help="Extract only encoding module.",
        action="store_true",
    )
    extract_parser.add_argument("extract", nargs="*", action=extractAction)

    prover_parser = subparsers.add_parser(
        "prove",
        help="""
        Run F*.

        This typechecks the extracted code.
        To lax-typecheck use --admit.
        """,
    )
    prover_parser.add_argument(
        "--admit",
        help="Admit all smt queries to lax typecheck.",
        action="store_true",
    )
    prover_parser.add_argument(
        "prove",
        nargs="*",
        action=proveAction,
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()


def main():
    # Don't print unnecessary Python stack traces.
    sys.tracebacklimit = 0
    parse_arguments()


if __name__ == "__main__":
    main()
