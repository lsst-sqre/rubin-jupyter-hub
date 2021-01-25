"""Setup module for Rubin JupyterHub Utilities.
"""
import codecs
import io
import os
import setuptools


def get_version(file, name="__version__"):
    """Get the version of the package from the given file by
    executing it and extracting the given `name`.
    """
    path = os.path.realpath(file)
    version_ns = {}
    with io.open(path, encoding="utf8") as f:
        exec(f.read(), {}, version_ns)
    return version_ns[name]


def local_read(filename):
    """Convenience function for includes.
    """
    full_filename = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), filename
    )
    return codecs.open(full_filename, "r", "utf-8").read()


NAME = "rubin_jupyter_utils.hub"
_path = NAME.replace(".", "/")
DESCRIPTION = "Rubin utilites for Jupyter Hub server environment"
LONG_DESCRIPTION = local_read("README.md")
VERSION = get_version("%s/_version.py" % _path)
AUTHOR = "Adam Thornton"
AUTHOR_EMAIL = "athornton@lsst.org"
URL = "https://github.com/sqre-lsst/rubin-jupyter-hub"
LICENSE = "MIT"
_scanrepo = NAME + ".scanrepo"

setuptools.setup(
    name=NAME,
    version=VERSION,
    long_description=LONG_DESCRIPTION,
    packages=setuptools.find_namespace_packages(
        include=["rubin_jupyter_utils.*"]
    ),
    url=URL,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    license=LICENSE,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: MIT License",
    ],
    keywords=["rubin", "jupyter", "jupyterhub", "hub"],
    install_requires=[
        "requests>=2,<3",
        "kubernetes>=11",
        "semver>=2,<3",
        "oauthenticator>=0.9,<1.0",
        "jupyter-client>=6,<7",
        "jupyterhub-jwtauthenticator>=0.1,<1.0",
        "jupyterhub-kubespawner>=0.13,<1.0",
        "jinja2>=2,<3",
        "pytz>=2020",
        "eliot>=1,<2",
        "eliot-tree>=19,<20",
        "argo-workflows>=3.2,<4.0",
        "asgiref>=3,<4",
        "pyyaml>=5",
        "rubin_jupyter_utils.helpers>=0.30.2,<1.0",
        "rubin_jupyter_utils.config>=0.31.0,<1.0",
    ],
    entry_points={
        "console_scripts": [
            "prepuller = " + _scanrepo + ":prepullerstandalone",
            "reaper = " + _scanrepo + ":reaperstandalone",
            "scanrepo = " + _scanrepo + ":standalone",
        ],
        "jupyterhub.authenticators": [
            (
                "RubinWebTokenAuthenticator = "
                + NAME
                + ".authenticator.RubinWebTokenAuthenticator"
            ),
        ],
        "jupyterhub.spawners": [
            "RubinSpawner = " + NAME + ".spawners.RubinSpawner",
        ],
    },
)
