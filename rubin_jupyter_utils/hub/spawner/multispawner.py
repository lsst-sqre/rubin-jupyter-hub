"""
JupyterHub Spawner to spawn user notebooks on a Kubernetes cluster in per-
user namespaces.

This module exports `NamespacedKubeSpawner` class, which is the spawner
implementation that should be used by JupyterHub.
"""

from kubernetes import config
from kubernetes.config.config_exception import ConfigException
from kubespawner import KubeSpawner
from .multireflector import (
    MultiNamespacePodReflector,
    MultiNamespaceEventReflector,
)
from rubin_jupyter_utils.helpers import make_logger


class MultiNamespacedKubeSpawner(KubeSpawner):
    """Implement a JupyterHub spawner to spawn pods in a Kubernetes Cluster
    with per-user namespaces.
    """

    def __init__(self, *args, **kwargs):
        if not self.log:
            self.log = make_logger()
        super().__init__(*args, **kwargs)
        self.delete_grace_period = 25  # K8s takes ten or so, usually
        self.namespace = self.get_user_namespace()
        try:
            self.log.debug("Loading K8s config.")
            config.load_incluster_config()
        except ConfigException:
            config.load_kube_config()
        self.log.debug(
            "Spawner __init__ done.  Namespace '{}'.".format(self.namespace)
        )

    def _start_watching_events(self, replace=True):
        return self._start_reflector(
            "events",
            MultiNamespaceEventReflector,
            fields={"involvedObject.kind": "Pod"},
            replace=replace,
        )

    def _start_watching_pods(self, replace=True):
        return self._start_reflector(
            "pods", MultiNamespacePodReflector, replace=replace
        )

    def _start_reflector(self, key, ReflectorClass, replace=True, **kwargs):
        def on_reflector_failure():
            self.log.critical(
                "%s reflector failed!", key.title(),
            )

        self.log.debug("Starting reflector {}".format(key.title()))
        previous_reflector = self.__class__.reflectors.get(key)

        if replace or not previous_reflector:
            self.__class__.reflectors[key] = ReflectorClass(
                namespace=self.namespace,
                parent=self,
                on_failure=on_reflector_failure,
                **kwargs,
            )

        if replace and previous_reflector:
            # we replaced the reflector, stop the old one
            previous_reflector.stop()

        # return the current reflector
        return self.__class__.reflectors[key]
