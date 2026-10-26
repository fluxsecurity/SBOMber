"""Test the real audit runner's publication gates using fake external tools."""
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("audit_inputs.sh")
CASE = "kirill89-prototype-pollution-explained"
SHA = "d7b5d98515a95f9a8cb0fedef034010ee083a6a9"
INPUTS = ("canonical-scan.json", "usage-graph.json", "localisation.json")


def executable(path, source):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    path.chmod(0o755)


@contextmanager
def sandbox(**overrides):
    with tempfile.TemporaryDirectory(prefix="s5-14-runner-test-") as temp:
        root = Path(temp)
        (root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, root / "scripts/audit_inputs.sh")
        (root / "scripts/versions.env").write_text("GO_VERSION=1.26.9\n")
        executable(root / "scripts/install-tools.sh", "#!/bin/sh\nexit 0\n")
        dest = root / "testdata/audit" / CASE
        dest.mkdir(parents=True)
        (dest / "CASE.md").write_text(SHA + "\n")
        for name in INPUTS:
            (dest / name).write_text("original evidence\n")
        repo = root / "audit-work" / CASE / "prototype-pollution-explained"
        (repo / ".git").mkdir(parents=True)
        previous = repo.parent / "out"
        previous.mkdir()
        (previous / "keep.txt").write_text("previous output\n")
        evidence = root / "docs/evidence/s5-14"
        evidence.mkdir(parents=True)
        (evidence / f"{CASE}.log").write_text("previous log\n")
        executable(root / "bin/sbomber", '''#!/bin/sh
out=''
while [ "$#" -gt 0 ]; do
 case "$1" in --out|--canonical-scan) shift; out=$1;; esac
 shift
done
printf '{"findings": []}\\n' > "$out"
''')
        tools = root / "fake-tools"
        executable(tools / "make", "#!/bin/sh\nexit 0\n")
        executable(tools / "grype", "#!/bin/sh\necho 'fake test database'\nexit 0\n")
        executable(tools / "git", f'''#!/bin/sh
case "$*" in
 *"status --porcelain"*)
   if [ "$2" = "$AUDIT_REVIEW_REPO" ] && [ "${{AUDIT_REVIEW_DIRTY:-0}}" = 1 ]; then
     echo ' M app.js'
   elif [ "$2" != "$AUDIT_REVIEW_REPO" ] && [ "${{AUDIT_REVIEW_SOURCE_DIRTY:-0}}" = 1 ]; then
     echo ' M internal/decision/state.go'
   fi;;
 *"checkout"*) touch "$AUDIT_REVIEW_CHECKOUT_CALLED";;
 *"log -1 --format=%ct"*) echo 1661874954;;
 *"rev-parse HEAD"*)
   if [ "$2" = "$AUDIT_REVIEW_REPO" ] && [ ! -e "$AUDIT_REVIEW_CHECKOUT_CALLED" ]; then
     echo "${{AUDIT_REVIEW_HEAD:-{SHA}}}"
   else
     echo {SHA}
   fi;;
esac
exit 0
''')
        executable(tools / "python3", f'''#!/bin/sh
case "$1" in
 */contracts/validate.py)
   echo "test validator exit $AUDIT_REVIEW_VALIDATION_EXIT"
   exit "$AUDIT_REVIEW_VALIDATION_EXIT";;
esac
if [ "$1" = '-c' ] && [ "$2" = 'import jsonschema' ]; then
 exit 0
fi
exec "{sys.executable}" "$@"
''')
        env = os.environ.copy()
        env.update({"PATH": str(tools) + os.pathsep + env.get("PATH", ""),
                    "GITHUB_TOKEN": "synthetic-runner-test-token",
                    "AUDIT_REVIEW_REPO": str(repo),
                    "AUDIT_REVIEW_CHECKOUT_CALLED": str(root / "checkout-called"),
                    "AUDIT_REVIEW_VALIDATION_EXIT": "0", **overrides})
        def run():
            return subprocess.run(["bash", str(root / "scripts/audit_inputs.sh"), CASE],
                                  env=env, text=True, capture_output=True, timeout=30)
        yield root, dest, run


class AuditInputPublicationTests(unittest.TestCase):
    def assert_preserved(self, dest):
        for name in INPUTS:
            self.assertEqual((dest / name).read_text(), "original evidence\n", name)

    def test_success_publishes_validated_inputs(self):
        with sandbox() as (_, dest, run):
            result = run()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in INPUTS:
                self.assertEqual((dest / name).read_text(), '{"findings": []}\n')
            self.assertFalse((dest / "labels.json").exists())

    def test_validation_failure_preserves_case_inputs(self):
        with sandbox(AUDIT_REVIEW_VALIDATION_EXIT="1") as (_, dest, run):
            result = run()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_preserved(dest)

    def test_dirty_cached_checkout_is_not_reset(self):
        with sandbox(AUDIT_REVIEW_DIRTY="1") as (root, dest, run):
            result = run()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((root / "checkout-called").exists())
            self.assert_preserved(dest)

    def test_wrong_cached_commit_is_not_reset(self):
        with sandbox(AUDIT_REVIEW_HEAD="0" * 40) as (root, dest, run):
            result = run()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((root / "checkout-called").exists())
            self.assert_preserved(dest)

    def test_existing_labels_prevent_input_refresh(self):
        with sandbox() as (_, dest, run):
            (dest / "labels.json").write_text("existing labels\n")
            result = run()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((dest / "labels.json").read_text(), "existing labels\n")
            self.assert_preserved(dest)

    def test_provisional_labels_prevent_input_refresh(self):
        with sandbox() as (_, dest, run):
            (dest / "labels.provisional.json").write_text("conditional labels\n")
            result = run()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((dest / "labels.provisional.json").read_text(), "conditional labels\n")
            self.assert_preserved(dest)

    def test_previous_run_output_and_log_are_preserved(self):
        with sandbox() as (root, _, run):
            result = run()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((root / "audit-work" / CASE / "out/keep.txt").exists(), "previous output was deleted")
            self.assertEqual((root / "audit-work" / CASE / "out/keep.txt").read_text(), "previous output\n")
            self.assertEqual((root / "docs/evidence/s5-14" / f"{CASE}.log").read_text(), "previous log\n")

    def test_uncommitted_production_source_is_rejected(self):
        with sandbox(AUDIT_REVIEW_SOURCE_DIRTY="1") as (_, dest, run):
            result = run()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_preserved(dest)


if __name__ == "__main__":
    unittest.main()
