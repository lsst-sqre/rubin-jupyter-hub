import json
from .. import Loggable
from .apimanager import RubinAPIManager
from .envmanager import RubinEnvironmentManager
from .namespacemanager import RubinNamespaceManager
from .optionsformmanager import RubinOptionsFormManager
from .quotamanager import RubinQuotaManager
from .volumemanager import RubinVolumeManager


class RubinMiddleManager(Loggable):
    """The RubinMiddleManager is a class that holds references to various
    Rubin-specific management objects and delegates requests to them.
    The idea is that an Rubin Spawner could instantiate a single
    RubinMiddleManager, which would then be empowered to perform all
    Rubin-specific operations, reducing configuration complexity.

    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = kwargs.pop("config", None)
        self.parent = kwargs.pop("parent", None)
        self.log.info(
            "Parent of Rubin Middle Manager is '{}'".format(self.parent)
        )
        self.authenticator = kwargs.pop("authenticator", None)
        self.spawner = kwargs.pop("spawner", None)
        self.user = kwargs.pop("user", None)
        self.api_mgr = RubinAPIManager(parent=self)
        self.env_mgr = RubinEnvironmentManager(parent=self)
        self.namespace_mgr = RubinNamespaceManager(parent=self)
        self.optionsform_mgr = RubinOptionsFormManager(parent=self)
        self.quota_mgr = RubinQuotaManager(parent=self)
        self.volume_mgr = RubinVolumeManager(parent=self)
        self.api = self.api_mgr.api
        self.rbac_api = self.api_mgr.rbac_api

    def dump(self):
        """Return contents dict to pretty-print.
        """
        md = {
            "parent": str(self.parent),
            "authenticator": str(self.authenticator),
            "api": str(self.api),
            "rbac_api": str(self.rbac_api),
            "config": self.config.dump(),
            "api_mgr": self.api_mgr.dump(),
            "env_mgr": self.env_mgr.dump(),
            "optionsform_mgr": self.optionsform_mgr.dump(),
            "quota_mgr": self.quota_mgr.dump(),
            "volume_mgr": self.volume_mgr.dump(),
        }
        if self.user:
            md["user"] = "{}".format(self.user)
        if self.spawner:
            md["spawner"] = self.spawner.dump()
        return md

    def toJSON(self):
        return json.dumps(self.dump())
