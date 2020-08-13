import json
import os
from eliot import start_action
from kubernetes.client import V1ResourceQuotaSpec
from kubernetes.client.rest import ApiException
from kubernetes import client
from .. import LoggableChild


class RubinQuotaManager(LoggableChild):
    """Quota support for Rubin LSP Jupyterlab and Dask pods.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.quota = {}
        self.custom_resources = {}
        self.resourcemap = None

    def define_resource_quota_spec(self):
        """We're going to return a resource quota spec that checks whether we
        have a custom resource map and uses that information.  If we do not
        then we use the quota from our parent's config object.

        Note that you could get a lot fancier, and check the user group
        memberships to determine what class a user belonged to, or some other
        more-sophisticated-than-one-size-fits-all quota mechanism.
        """
        with start_action(action_type="define_resource_quota_spec"):
            self.log.debug("Calculating default resource quotas.")
            om = self.parent.optionsform_mgr
            sizemap = om.sizemap
            # sizemap is an ordered dict, and we want the last-inserted one,
            #  which is the biggest
            big = list(sizemap.keys())[-1]
            cpu = sizemap[big]["cpu"]
            cfg = self.parent.config
            max_dask_workers = 0
            if cfg.allow_dask_spawn:
                max_dask_workers = cfg.max_dask_workers
            mem_per_cpu = cfg.mb_per_cpu
            total_cpu = (1 + max_dask_workers) * cpu
            total_mem = str(int(total_cpu * mem_per_cpu + 0.5)) + "Mi"
            total_cpu = str(int(total_cpu + 0.5))
            self.log.debug(
                "Default quota sizes: CPU %r, mem %r" % (total_cpu, total_mem)
            )
            self._set_custom_user_resources()
            if self.custom_resources:
                self.log.debug("Have custom resources.")
                cpuq = self.custom_resources.get("cpu_quota")
                if cpuq:
                    self.log.debug("Overriding CPU quota.")
                    total_cpu = str(cpuq)
                memq = self.custom_resources.get("mem_quota")
                if memq:
                    self.log.debug("Overriding memory quota.")
                    total_mem = str(memq) + "Mi"
            self.log.debug(
                "Determined quota sizes: CPU %r, mem %r"
                % (total_cpu, total_mem)
            )
            qs = V1ResourceQuotaSpec(
                hard={"limits.cpu": total_cpu, "limits.memory": total_mem}
            )
            self.quota = qs.hard

    def _set_custom_user_resources(self):
        """Create custom resource definitions for user.
        """
        with start_action(action_type="_set_custom_user_resources"):
            if not self.resourcemap:
                self.log.debug("No resource map found; generating.")
                self._create_resource_map()
            if not self.resourcemap:
                self.log.warning("No resource map; cannot generate quota.")
                return
            resources = {"size_index": 0, "cpu_quota": 0, "mem_quota": 0}
            gnames = self.parent.user.groups
            uname = self.parent.user.escaped_name
            for resdef in self.resourcemap:
                apply = False
                if resdef.get("disabled"):
                    continue
                candidate = resdef.get("resources")
                if not candidate:
                    continue
                self.log.debug(
                    "Considering candidate resource map {}".format(resdef)
                )
                ruser = resdef.get("user")
                rgroup = resdef.get("group")
                if ruser and ruser == uname:
                    self.log.debug("User resource map match.")
                    apply = True
                if rgroup and rgroup in gnames:
                    self.log.debug("Group resource map match.")
                    apply = True
                if apply:
                    for fld in ["size_index", "cpu_quota", "mem_quota"]:
                        vv = candidate.get(fld)
                        if vv and vv > resources[fld]:
                            resources[fld] = vv
                        self.log.debug(
                            "Setting custom resources '{}'".format(resources)
                            + "for user '{}'".format(uname)
                        )
                        self.custom_resources = resources

    def _create_resource_map(self):
        with start_action(action_type="_create_resource_map"):
            resource_file = self.parent.config.resource_map
            if not os.path.exists(resource_file):
                nf_msg = (
                    "Could not find resource definition file"
                    + " at '{}'".format(resource_file)
                )
                self.log.error(nf_msg)
                return
            with open(resource_file, "r") as rf:
                resmap = json.load(rf)
            self.resourcemap = resmap

    # Brought in from namespacedkubespawner
    def ensure_namespaced_resource_quota(self, quotaspec):
        """Create K8s quota object if necessary.
        """
        with start_action(action_type="ensure_namespaced_resource_quota"):
            self.log.debug("Entering ensure_namespaced_resource_quota()")
            namespace = self.parent.namespace_mgr.namespace
            api = self.parent.api
            if namespace == "default":
                self.log.error("Will not create quota for default namespace!")
                return
            quota = client.V1ResourceQuota(
                metadata=client.V1ObjectMeta(name="quota",), spec=quotaspec
            )
            self.log.info("Creating quota: %r" % quota)
            try:
                api.create_namespaced_resource_quota(namespace, quota)
            except ApiException as e:
                if e.status != 409:
                    self.log.exception(
                        "Create resourcequota '%s'" % quota
                        + "in namespace '%s' " % namespace
                        + "failed: %s",
                        str(e),
                    )
                    raise
                else:
                    self.log.debug(
                        "Resourcequota '%r' " % quota
                        + "already exists in '%s'." % namespace
                    )

    def destroy_namespaced_resource_quota(self):
        """Destroys the Kubernetes namespaced resource quota.
        You don't usually have to call this, since it will get
        cleaned up as part of namespace deletion.
        """
        with start_action(action_type="destroy_namespaced_resource_quota"):
            namespace = self.parent.namespace_mgr.namespace
            api = self.parent.api
            qname = "quota-" + namespace
            dopts = client.V1DeleteOptions()
            self.log.info("Deleting resourcequota '%s'" % qname)
            api.delete_namespaced_resource_quota(qname, namespace, dopts)

    def dump(self):
        """Return contents dict for pretty-printing/aggregation.
        """
        qd = {
            "parent": str(self.parent),
            "quota": self.quota,
            "custom_resources": self.custom_resources,
            "resourcemap": self.resourcemap,
        }
        return qd

    def toJSON(self):
        return json.dumps(self.dump())
