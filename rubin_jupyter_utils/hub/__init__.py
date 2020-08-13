"""Rubin JupyterHub utilities and helpers.

These implement the Rubin-specific tooling for the Rubin Science
Platform Notebook Aspect.  The repo scanner looks for Docker images in
a repository with a particular tag format; the prepuller pulls a
subset of those images to each node.  The reaper removes images past a
certain age, based on the tag format.  The Rubin Manager class provides
a hierarchy of objects that hold Rubin-specific configuration and logic
for spawning JupyterLab pods, and the spawner and authenticators
provide the pod spawner and the Rubin-supported authentication methods
and logic.  Convenience functions are in 'utils' and JupyterHub
configuration convenience functions are in 'config_helpers'.
"""
from .loggable import Loggable, LoggableChild
from .scanrepo import ScanRepo, SingletonScanner, Prepuller, Reaper
from .rubinmgr import RubinMiddleManager
from .spawner import RubinSpawner
from .authenticator.rubinwebtokenauthenticator import (
    RubinWebTokenAuthenticator,
)
from ._version import __version__

__all__ = [
    RubinMiddleManager,
    Prepuller,
    Reaper,
    ScanRepo,
    SingletonScanner,
    RubinSpawner,
    RubinWebTokenAuthenticator,
    Loggable,
    LoggableChild,
    __version__,
]
