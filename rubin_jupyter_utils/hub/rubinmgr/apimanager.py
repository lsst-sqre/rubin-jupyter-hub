import json
from .. import LoggableChild
from rubin_jupyter_utils.helpers import Singleton
from kubernetes.client import CoreV1Api, RbacAuthorizationV1Api
from kubernetes.config import load_incluster_config, load_kube_config
from kubernetes.config.config_exception import ConfigException


class RubinAPIManager(LoggableChild, metaclass=Singleton):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            load_incluster_config()
        except ConfigException:
            self.log.warning("In-cluster config failed! Falling back.")
            try:
                load_kube_config()
            except ValueError as exc:
                self.log.error("Still errored: {}".format(exc))
        rbac_api = kwargs.pop("rbac_api", None)
        if not rbac_api:
            rbac_api = RbacAuthorizationV1Api()
        self.rbac_api = rbac_api
        api = kwargs.pop("api", None)
        if not api:
            api = CoreV1Api()
        self.api = api

    def dump(self):
        """Return contents dict for aggregation and pretty-printing.
        """
        ad = {
            "parent": str(self.parent),
            "api": str(self.api),
            "rbac_api": str(self.rbac_api),
        }
        return ad

    def toJSON(self):
        return json.dumps(self.dump())
