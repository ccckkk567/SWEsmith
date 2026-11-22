"""Evaluate a SWE-smith task against a caller-supplied SIF on Linux."""

import os
import signal
import subprocess
import tempfile
from pathlib import Path

from swebench.harness.constants import DOCKER_PATCH, LOG_INSTANCE, LOG_TEST_OUTPUT, TESTS_TIMEOUT
from swebench.harness.docker_build import setup_logger
from unidiff import PatchSet

from swesmith.constants import GIT_APPLY_CMDS, TEST_OUTPUT_END, TEST_OUTPUT_START


def _exec(sif, binds, args, *, cwd="/", timeout=300, check=True):
    command = ["apptainer", "exec", "--containall", "--cleanenv", "--no-mount",
               "home,cwd,hostfs,bind-paths", "--pwd", cwd]
    for source, dest in binds:
        command.extend(["--bind", f"{source}:{dest}:rw"])
    # Ignore inherited binds, including those exported by a parent container.
    env = os.environ.copy()
    for prefix in ("APPTAINER", "SINGULARITY"):
        for suffix in ("_BIND", "_BINDPATH", "_MOUNT", "ENV_HOME"):
            env.pop(prefix + suffix, None)
    with subprocess.Popen([*command, str(sif), *args], env=env, start_new_session=True,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, errors="replace") as process:
        try:
            output, _ = process.communicate(timeout=timeout)
        except BaseException as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = process.communicate()
            if isinstance(exc, subprocess.TimeoutExpired):
                exc.output = output
            raise
        if check and process.returncode:
            raise RuntimeError(f"{args[0]} exited with {process.returncode}: {output}")
        return process.returncode, output


def run_patch(instance, profile, patch, directory, sif, work_dir, *, is_gold, f2p_only):
    iid = instance["instance_id"]
    logger = setup_logger(f"apptainer.{directory}", directory / LOG_INSTANCE)
    output_path = directory / LOG_TEST_OUTPUT
    try:
        sif = Path(sif).resolve(strict=True)
        work_dir = Path(work_dir).resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="swesmith-", dir=work_dir) as attempt:
            work = Path(attempt)
            repo, tmp = work / "testbed", work / "tmp"
            repo.mkdir()
            tmp.mkdir()
            logger.info("Evaluating %s with %s in %s", iid, sif, work)
            _exec(sif, [(repo, "/stage")], ["bash", "-ec",
                  "cp -a --no-preserve=ownership /testbed/. /stage/ && chmod -R u+rwX /stage && test -d /stage/.git"])

            def execute(args, **kwargs):
                return _exec(sif, [(repo, "/testbed"), (tmp, "/tmp")], args, cwd="/testbed", **kwargs)

            if execute(["git", "checkout", iid], check=False)[0]:
                execute(["git", "fetch", "origin"])
                execute(["git", "checkout", iid])
            execute(["git", "checkout", "HEAD~1"])
            if patch:
                (directory / "patch.diff").write_text(patch, encoding="utf-8")
                paths = [file.path for file in PatchSet(patch)]
                if paths:
                    _, tracked = execute(["git", "ls-files", "-z", "--", *paths])
                    if tracked:
                        execute(["git", "checkout", "--", *tracked.rstrip("\0").split("\0")])
                with (tmp / Path(DOCKER_PATCH).name).open("x", encoding="utf-8") as file:
                    file.write(patch)
                for method in GIT_APPLY_CMDS:
                    args = method.split()
                    # Insert switches before the final -i operand of the patch fallback.
                    pos = 2 if args[0] == "git" else 1
                    if args[0] == "patch":
                        args.insert(pos, "--forward")  # Never guess the opposite patch direction.
                    if is_gold:
                        args.insert(pos, "--reverse")
                    probe = args.copy()
                    probe.insert(pos, "--check" if args[0] == "git" else "--dry-run")
                    rc, output = execute([*probe, DOCKER_PATCH], check=False)
                    if rc == 0:
                        execute([*args, DOCKER_PATCH])
                        break
                    logger.info("Patch check failed: %s", output)
                else:
                    raise RuntimeError("Could not apply patch")
                f2p, p2p = profile.get_test_files(instance)
                if f2p or p2p:
                    execute(["git", "checkout", "HEAD", "--", *f2p, *p2p])

            test_cmd, _ = profile.get_test_cmd(instance, f2p_only=f2p_only)
            script = "\n".join(["#!/bin/bash", "set -uxo pipefail", "cd /testbed",
                                f": '{TEST_OUTPUT_START}'", "(", test_cmd, ")", "rc=$?",
                                f": '{TEST_OUTPUT_END}'", 'exit "$rc"', ""])
            (directory / "eval.sh").write_text(script, encoding="utf-8")
            with (tmp / "eval.sh").open("x", encoding="utf-8") as file:
                file.write(script)
            try:
                rc, output = execute(["bash", "/tmp/eval.sh"], timeout=profile.timeout, check=False)
            except subprocess.TimeoutExpired as exc:
                output = f"{exc.output or ''}\n\n{TESTS_TIMEOUT}: {profile.timeout} seconds exceeded"
                timed_out = True
            else:
                if rc in (126, 127) or f"+ : '{TEST_OUTPUT_END}'" not in output:
                    raise RuntimeError(f"Test command did not finish normally ({rc}): {output}")
                timed_out = False
        output_path.write_text(output, encoding="utf-8")
        return logger, timed_out
    except Exception:
        logger.exception("Apptainer evaluation failed for %s", iid)
        output_path.unlink(missing_ok=True)
        return logger, False
