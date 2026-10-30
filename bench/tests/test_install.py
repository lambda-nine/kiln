import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


class InstallTargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        scripts = self.root / "repo" / "scripts"
        scripts.mkdir(parents=True)
        shutil.copy2(REPO / "scripts" / "install.sh", scripts / "install.sh")

        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.install_dest = self.root / "installed kiln"
        self._executable("cargo", '''#!/bin/sh
set -eu
target_dir=
while [ "$#" -gt 0 ]; do
    if [ "$1" = --target-dir ]; then
        shift
        target_dir=$1
    fi
    shift
done
if [ -z "$target_dir" ]; then
    target_dir=${CARGO_TARGET_DIR:-target}
fi
mkdir -p "$target_dir/release"
printf '%s\\n' fresh-artifact > "$target_dir/release/kiln"
''')
        self._executable("sudo", '''#!/bin/sh
# The fixture only needs to model the kiln install; service installs succeed.
if [ "$1" = install ] && [ "$2" = -m ] && [ "$3" = 755 ]; then
    source=$4
    destination=$5
    if [ "$destination" = /usr/local/bin/kiln ]; then
        cp "$source" "$INSTALL_DEST"
        printf '%s\\n' "$source" > "$INSTALL_RECORD"
    fi
fi
exit 0
''')
        self._executable("systemctl", "#!/bin/sh\nexit 0\n")
        self.env = os.environ.copy()
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]
        self.env["INSTALL_DEST"] = str(self.install_dest)
        self.env["INSTALL_RECORD"] = str(self.root / "install-record")

    def tearDown(self):
        self.temp.cleanup()

    def _executable(self, name, contents):
        path = self.bin / name
        path.write_text(contents)
        path.chmod(0o755)

    def run_install(self, target_dir=None):
        env = self.env.copy()
        if target_dir is None:
            env.pop("CARGO_TARGET_DIR", None)
        else:
            env["CARGO_TARGET_DIR"] = str(target_dir)
        result = subprocess.run(
            ["sh", "scripts/install.sh"],
            cwd=self.root / "repo",
            env=env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.install_dest.read_text(), "fresh-artifact\n")

    def test_default_target_uses_fresh_artifact_with_stale_target_present(self):
        stale = self.root / "repo" / "target" / "release"
        stale.mkdir(parents=True)
        (stale / "kiln").write_text("stale-artifact\n")

        self.run_install()

        self.assertEqual(
            Path(self.env["INSTALL_RECORD"]).read_text(),
            "target/release/kiln\n",
        )

    def test_absolute_target_directory_with_spaces(self):
        target_dir = self.root / "absolute target directory"
        self.run_install(target_dir)
        self.assertEqual(
            Path(self.env["INSTALL_RECORD"]).read_text(),
            f"{target_dir}/release/kiln\n",
        )

    def test_relative_target_directory_with_spaces(self):
        relative = Path("relative target directory")
        self.run_install(relative)
        self.assertEqual(
            Path(self.env["INSTALL_RECORD"]).read_text(),
            f"{relative}/release/kiln\n",
        )


if __name__ == "__main__":
    unittest.main()
