"""Class to provide namespace manipulation.
"""

import json
import time
import yaml
from eliot import start_action
from kubernetes.client.rest import ApiException
from kubernetes import client
from .. import LoggableChild
from rubin_jupyter_utils.helpers import (
    make_passwd_line,
    make_group_lines,
    add_user_to_groups,
    assemble_gids,
    get_pull_secret,
    get_pull_secret_reflist,
)


class RubinNamespaceManager(LoggableChild):
    """Class to provide namespace manipulation.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.namespace = None
        self.service_account = None  # Account for pod to run as

    def set_namespace(self, namespace):
        with start_action(action_type="set_namespace"):
            self.namespace = namespace

    def ensure_namespace(self, namespace=None, daskconfig=None):
        """Here we make sure that the namespace exists, creating it if
        it does not.  That requires a ClusterRole that can list and create
        namespaces.

        If we create the namespace, we also create (if needed) a ServiceAccount
        within it to allow the user pod to spawn dask and workflow pods.

        """
        with start_action(action_type="ensure_namespace"):
            if not namespace:
                namespace = self.namespace
            else:
                self.set_namespace(namespace)
            if not namespace or namespace == "default":
                raise ValueError("Will not use default namespace!")
            api = self.parent.api
            cfg = self.parent.config
            acd = "argocd.argoproj.io/"
            ns = client.V1Namespace(
                metadata=client.V1ObjectMeta(
                    name=namespace,
                    labels={acd + "instance": "nublado-users"},
                    annotations={
                        acd + "compare-options": "IgnoreExtraneous",
                        acd + "sync-options": "Prune=false",
                    },
                )
            )
            try:
                self.log.info(
                    "Attempting to create namespace '%s'" % namespace
                )
                api.create_namespace(ns)
            except ApiException as e:
                if e.status != 409:
                    estr = "Create namespace '%s' failed: %s" % (ns, str(e))
                    self.log.exception(estr)
                    raise
                else:
                    self.log.info("Namespace '%s' already exists." % namespace)
            # Wait for the namespace to actually appear before creating objects
            #  in it.
            self.wait_for_namespace()
            self.log.debug("Ensuring namespaced config maps.")
            self.ensure_namespaced_config_maps()
            if cfg.allow_dask_spawn:
                self.log.debug("Ensuring namespaced service account.")
                self.ensure_namespaced_service_account()
                if daskconfig:
                    self.ensure_dask_configmap(daskconfig)
            if self.parent.spawner.enable_namespace_quotas:
                # By the time we need this, quota will have been set, because
                #  we needed it for options form generation.
                self.log.debug("Determining resource quota.")
                qm = self.parent.quota_mgr
                qm.ensure_namespaced_resource_quota(qm.quota)
            self.log.debug("Namespace resources ensured.")

    def def_namespaced_account_objects(self):
        """Define K8s objects for things we need in the namespace.
        """
        with start_action(action_type="define_namespaced_account_objects"):
            namespace = self.namespace
            username = self.parent.user.escaped_name

            cfg = self.parent.config
            pull_secret = get_pull_secret(cfg)
            pull_secret_ref = get_pull_secret_reflist(pull_secret)

            account = "{}-svcacct".format(username)
            self.service_account = account
            acd = "argocd.argoproj.io/"
            md = client.V1ObjectMeta(
                name=account,
                labels={acd + "instance": "nublado-users"},
                annotations={
                    acd + "compare-options": "IgnoreExtraneous",
                    acd + "sync-options": "Prune=false",
                },
            )
            svcacct = client.V1ServiceAccount(
                metadata=md, image_pull_secrets=pull_secret_ref
            )

            # These rules let us manipulate Dask pods, Argo Workflows, and
            #  Multus CNI interfaces
            rules = [
                client.V1PolicyRule(
                    api_groups=["argoproj.io"],
                    resources=["workflows", "workflows/finalizers"],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "update",
                        "patch",
                        "create",
                        "delete",
                    ],
                ),
                client.V1PolicyRule(
                    api_groups=["argoproj.io"],
                    resources=[
                        "workflowtemplates",
                        "workflowtemplates/finalizers",
                    ],
                    verbs=["get", "list", "watch"],
                ),
                client.V1PolicyRule(
                    api_groups=[""], resources=["secrets"], verbs=["get"]
                ),
                client.V1PolicyRule(
                    api_groups=[""],
                    resources=["pods", "pods/exec", "services", "configmaps"],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "delete",
                        "update",
                        "patch",
                    ],
                ),
                client.V1PolicyRule(
                    api_groups=[""],
                    resources=["pods/log", "serviceaccounts"],
                    verbs=["get", "list", "watch"],
                ),
            ]
            role = client.V1Role(rules=rules, metadata=md)
            rbstr = "rbac.authorization.k8s.io"
            rolebinding = client.V1RoleBinding(
                metadata=md,
                role_ref=client.V1RoleRef(
                    api_group=rbstr, kind="Role", name=account
                ),
                subjects=[
                    client.V1Subject(
                        kind="ServiceAccount",
                        name=account,
                        namespace=namespace,
                    )
                ],
            )
            return pull_secret, svcacct, role, rolebinding

    def ensure_namespaced_service_account(self):
        """Create a service account with role and rolebinding to allow it
        to manipulate resources in the namespace.
        """
        with start_action(action_type="ensure_namespaced_service_account"):
            self.log.info("Ensuring namespaced service account.")
            namespace = self.namespace
            api = self.parent.api
            rbac_api = self.parent.rbac_api
            (
                pull_secret,
                svcacct,
                role,
                rolebinding,
            ) = self.def_namespaced_account_objects()
            account = self.service_account

            try:
                self.log.info("Attempting to create pull secret.")
                api.create_namespaced_secret(
                    namespace=namespace, body=pull_secret
                )
            except ApiException as e:
                if e.status != 409:
                    self.log.exception(
                        (
                            "Create pull secret '{}' "
                            + "in namespace '{}' "
                            + "failed: '{}"
                        ).format(account, namespace, e)
                    )
                    raise
                else:
                    self.log.info(
                        (
                            "Pull secret '{}' "
                            + "in namespace '{}' "
                            + "already exists."
                        ).format(account, namespace)
                    )

            try:
                self.log.info("Attempting to create service account.")
                api.create_namespaced_service_account(
                    namespace=namespace, body=svcacct
                )
            except ApiException as e:
                if e.status != 409:
                    self.log.exception(
                        (
                            "Create service account '{}' "
                            + "in namespace '{}' "
                            + "failed: '{}"
                        ).format(account, namespace, e)
                    )
                    raise
                else:
                    self.log.info(
                        (
                            "Service account '{}' "
                            + "in namespace '{}' "
                            + "already exists."
                        ).format(account, namespace)
                    )
            try:
                self.log.info("Attempting to create role in namespace.")
                rbac_api.create_namespaced_role(namespace, role)
            except ApiException as e:
                if e.status != 409:
                    self.log.exception(
                        (
                            "Create role '{}' "
                            + "in namespace '{}' "
                            + "failed: {}"
                        ).format(account, namespace, e)
                    )
                    raise
                else:
                    self.log.info(
                        (
                            "Role '{}' already exists in " + "namespace '{}'."
                        ).format(account, namespace)
                    )
            try:
                self.log.info("Attempting to create rolebinding in namespace.")
                rbac_api.create_namespaced_role_binding(namespace, rolebinding)
            except ApiException as e:
                if e.status != 409:
                    self.log.exception(
                        (
                            "Create rolebinding '{}' "
                            + "in namespace '{}' "
                            + "failed: {}"
                        ).format(account, namespace, e)
                    )
                    raise
                else:
                    self.log.info(
                        "Rolebinding '%s' " % account
                        + "already exists in '%s'." % namespace
                    )

    def def_lab_config_maps(self):
        """Create ConfigMaps for data we will need in the
        spawned environment.  Returns a dict with string keys which are
        the basenames of the ConfigMap-represented files, and values
        which are the in-memory K8s ConfigMap objects.
        """
        with start_action(action_type="def_lab_config_maps"):
            cfg = self.parent.config
            # This is a sort of gross way to get around the fact that
            # accessing auth_state is an async function but wfdispatcher,
            # which also uses this method, is not an async framework.
            #
            # Since the spawner is a per-session object, it can hold a
            #  cached auth state which shouldn't change during a spawning
            #  session.
            ast = self.parent.spawner.cached_auth_state
            if not ast:
                errstr = "Spawner has no cached_auth_state!"
                self.log.error(errstr)
                raise RuntimeError(errstr)
            uname = ast["claims"]["uid"]
            token = ast["access_token"]
            claims = ast["claims"]
            vol_file = cfg.volume_definition_file
            with open(vol_file, "r") as fp:
                vdata = fp.read()
            v_nm = "mountpoints"
            vol_configmap = client.V1ConfigMap(
                metadata=client.V1ObjectMeta(name=v_nm), data={v_nm: vdata}
            )
            self.log.debug("Created volume configmap '{}'".format(v_nm))
            pw_file = cfg.base_passwd_file
            with open(pw_file, "r") as fp:
                b_pdata = fp.read().rstrip() + "\n"
            p_nm = "passwd"
            pline = make_passwd_line(claims)
            pdata = b_pdata + pline
            pw_configmap = client.V1ConfigMap(
                metadata=client.V1ObjectMeta(name=p_nm), data={p_nm: pdata}
            )
            grp_file = cfg.base_group_file
            with open(grp_file, "r") as fp:
                b_gdata = fp.read().rstrip() + "\n"
            gdata = add_user_to_groups(uname, b_gdata)
            g_nm = "group"
            glines = make_group_lines(
                claims, strict_ldap=cfg.strict_ldap_groups
            )
            for gl in glines:
                gdata = gdata + gl
            grp_configmap = client.V1ConfigMap(
                metadata=client.V1ObjectMeta(name=g_nm), data={g_nm: gdata}
            )
            a_nm = "access-token"
            # Use fqdn to uniquely identify instance.
            mt_nm = cfg.fqdn + "-token"
            at_configmap = client.V1ConfigMap(
                metadata=client.V1ObjectMeta(name=a_nm), data={mt_nm: token}
            )
            s_nm = "shadow"
            s_pw_configmap = client.V1ConfigMap(
                metadata=client.V1ObjectMeta(name=s_nm),
                data={s_nm: self._pwconv(pdata)},
            )
            sg_nm = "gshadow"
            s_grp_configmap = client.V1ConfigMap(
                metadata=client.V1ObjectMeta(name=sg_nm),
                data={sg_nm: self._grpconv(gdata)},
            )
            cm_map = {
                v_nm: vol_configmap,
                p_nm: pw_configmap,
                s_nm: s_pw_configmap,
                g_nm: grp_configmap,
                sg_nm: s_grp_configmap,
                a_nm: at_configmap,
            }
            return cm_map

    def ensure_dask_configmap(self, daskconfig):
        """This one can't be called until we know the parameters (image, size,
        etc.) (typically spawn time).  Daskconfig is a dict with string keys.
        """
        with start_action(action_type="ensure_dask_configmap"):
            namespace = self.namespace
            api = self.parent.api
            cfg = self.parent.config
            if not cfg.allow_dask_spawn:
                self.log.warning(
                    "Dask spawns disallowed.  Not making configmap."
                )
                return
            dask_config = self._def_dask_configmap(daskconfig)
            try:
                self.log.info(
                    (
                        (
                            "Attempting to create configmap 'dask-config' "
                            + "in {}"
                        ).format(namespace)
                    )
                )
                api.create_namespaced_config_map(namespace, dask_config)
            except ApiException as e:
                if e.status != 409:
                    estr = "Create configmap failed: {}".format(e)
                    self.log.exception(estr)
                    raise
                else:
                    self.log.info("Configmap already exists.")

    def _def_dask_configmap(self, daskconfig):
        with start_action(action_type="_def_dask_configmap"):
            d_yaml = self._def_dask_yaml(daskconfig)
            # Same per-instance strategy as access_token
            fqdn = self.parent.config.fqdn
            fn = fqdn + "-dask_worker.example.yml"
            cmap = client.V1ConfigMap(
                metadata=client.V1ObjectMeta(name="dask-config"),
                data={fn: d_yaml},
            )
            return cmap

    def _def_dask_yaml(self, daskconfig):
        with start_action(action_type="_def_dask_yaml"):
            cfg = self.parent.config
            vm = self.parent.volume_mgr
            ast = daskconfig["auth_state"]
            claims = ast["claims"]
            uname = claims["uid"]
            uid = int(ast["uid"])
            uid_str = str(ast["uid"])
            debug = ""
            instance_name = ""
            if daskconfig.get("instance_name"):
                instance_name = daskconfig["instance_name"]
            if daskconfig["debug"]:
                debug = "true"
            e_grps = assemble_gids(claims, strict_ldap=cfg.strict_ldap_groups)
            resources = daskconfig["resources"]
            image = daskconfig["image"]
            cmd = "/opt/lsst/software/jupyterlab/provisionator.bash"
            mounts = vm.get_volume_mount_list()
            vols = vm.get_volume_list()
            run_as = 769
            if cfg.lab_no_sudo:
                run_as = uid
            dask_ctr = {
                "image": image,
                "imagePullPolicy": "Always",
                "args": [cmd],
                "name": "dask",
                "env": [
                    {"name": "DASK_WORKER", "value": "true"},
                    {"name": "DEBUG", "value": debug},
                    {"name": "EXTERNAL_GROUPS", "value": e_grps},
                    {"name": "EXTERNAL_UID", "value": uid_str},
                    {"name": "JUPYTERHUB_USER", "value": uname},
                    {"name": "INSTANCE_NAME", "value": instance_name},
                    {"name": "CPU_LIMIT", "value": resources["limits"]["cpu"]},
                    {
                        "name": "MEM_LIMIT",
                        "value": resources["limits"]["memory"],
                    },
                    {
                        "name": "CPU_GUARANTEE",
                        "value": resources["requests"]["cpu"],
                    },
                    {
                        "name": "MEM_GUARANTEE",
                        "value": resources["requests"]["memory"],
                    },
                ],  # env
                "resources": resources,
                "volumeMounts": mounts,
            }
            if cfg.restrict_dask_nodes:
                dask_ctr["nodeSelector"] = {"dask": "ok"}
            self.log.error("Dask container: {}".format(dask_ctr))
            self.log.error("Volumes: {}".format(vols))
            dask_spec = {
                "restartPolicy": "Never",
                "securityContext": {"runAsUser": run_as, "runAsGroup": run_as},
            }
            self.log.error("Dask_spec_pre: {}".format(dask_spec))
            dask_spec["containers"] = [dask_ctr]
            self.log.error("Dask_spec_pre2: {}".format(dask_spec))
            dask_spec["volumes"] = vols
            self.log.error("Dask_spec_post: {}".format(dask_spec))
            dask_dict = {
                "kind": "Pod",
                "metadata": {"labels": {"dask": "ok"}},
                "spec": dask_spec,
            }
            self.log.error("Dask pod object: {}".format(dask_dict))
            c_yaml = yaml.dump(dask_dict)
            self.log.error("Dask YAML: {}".format(c_yaml))
            return c_yaml

    def _pwconv(self, pwdata):
        pwlines = pwdata.split("\n")
        spwlines = []
        for pl in pwlines:
            pll = pl.strip()
            if not pll:
                continue
            unm = pll.split(":")[0]
            # 18000 is late March 2019; doesn't really matter
            spl = "{}:*:18000:0:99999:7:::\n".format(unm)
            spwlines.append(spl)
        spwdata = "".join(spwlines)  # They already have newlines
        return spwdata

    def _grpconv(self, grpdata):
        grplines = grpdata.split("\n")
        sglines = []
        for grp in grplines:
            grpl = grp.strip()
            if not grpl:
                continue
            flds = grpl.split(":")
            gnm = flds[0]
            gmem = flds[-1]
            sgl = "{}:!::{}\n".format(gnm, gmem)
            sglines.append(sgl)
        sgdata = "".join(sglines)  # They already have newlines
        return sgdata

    def ensure_namespaced_config_maps(self):
        with start_action(action_type="ensure_namespaced_config_maps"):
            namespace = self.namespace
            api = self.parent.api
            cm_map = self.def_lab_config_maps()
            for cm in cm_map:
                try:
                    self.log.info(
                        (
                            (
                                "Attempting to create configmap {} " + "in {}"
                            ).format(cm, namespace)
                        )
                    )
                    api.create_namespaced_config_map(namespace, cm_map[cm])
                except ApiException as e:
                    if e.status != 409:
                        estr = "Create configmap failed: {}".format(e)
                        self.log.exception(estr)
                        raise
                    else:
                        self.log.info("Configmap already exists.")

    def wait_for_namespace(self, timeout=30):
        """Wait for namespace to be created."""
        with start_action(action_type="wait_for_namespace"):
            namespace = self.namespace
            for dl in range(timeout):
                self.log.debug(
                    "Checking for namespace "
                    + "{} [{}/{}]".format(namespace, dl, timeout)
                )
                nl = self.parent.api.list_namespace(timeout_seconds=1)
                for ns in nl.items:
                    nsname = ns.metadata.name
                    if nsname == namespace:
                        self.log.debug("Namespace {} found.".format(namespace))
                        return
                    self.log.debug(
                        "Namespace {} not present yet.".format(namespace)
                    )
                time.sleep(1)
            raise RuntimeError(
                "Namespace '{}' not created in {} seconds!".format(
                    namespace, timeout
                )
            )

    def maybe_delete_namespace(self):
        """Here we try to delete the namespace.  If it has no non-dask
        running pods, and it's not the default namespace, we can delete it."

        This requires a cluster role that can delete namespaces."""
        with start_action(action_type="maybe_delete_namespace"):
            self.log.debug("Attempting to delete namespace.")
            namespace = self.namespace
            if not namespace or namespace == "default":
                raise RuntimeError("Cannot delete default namespace!")
            podlist = self.parent.api.list_namespaced_pod(namespace)
            clear_to_delete = True
            if podlist and podlist.items:
                clear_to_delete = self._check_pods(podlist.items)
            if not clear_to_delete:
                self.log.info("Not deleting namespace '%s'" % namespace)
                return False
            self.log.info("Deleting namespace '%s'" % namespace)
            self.parent.api.delete_namespace(namespace)
            return True

    def _check_pods(self, items):
        with start_action(action_type="_check_pods"):
            namespace = self.namespace
            for i in items:
                if i and i.status:
                    phase = i.status.phase
                    if (
                        phase == "Running"
                        or phase == "Unknown"
                        or phase == "Pending"
                    ):
                        pname = i.metadata.name
                        if pname.startswith("dask-"):
                            self.log.debug(
                                (
                                    "Abandoned dask pod '{}' can be "
                                    + "reaped."
                                ).format(pname)
                            )
                            # We can murder abandoned dask pods
                            continue
                        self.log.warning(
                            (
                                "Pod in state '{}'; cannot delete "
                                + "namespace '{}'."
                            ).format(phase, namespace)
                        )
                        return False
            # FIXME check on workflows as well.
            return True

    def destroy_namespaced_resource_quota(self):
        """Remove quotas from namespace.
        You don't usually have to call this, since it will get
        cleaned up as part of namespace deletion.
        """
        with start_action(action_type="destroy_namespaced_resource_quota"):
            namespace = self.get_user_namespace()
            api = self.parent.api
            qname = "quota-" + namespace
            dopts = client.V1DeleteOptions()
            self.log.info("Deleting resourcequota '%s'" % qname)
            api.delete_namespaced_resource_quota(qname, namespace, dopts)

    def delete_namespaced_svcacct_objs(self):
        """Remove service accounts, roles, and rolebindings from namespace.
        You don't usually have to call this, since they will get
         cleaned up as part of namespace deletion.
        """
        with start_action(action_type="delete_namespaced_svcacct_objs"):
            namespace = self.namespace
            account = self.service_account
            if not account:
                self.log.info("Service account not defined.")
                return
            dopts = client.V1DeleteOptions()
            self.log.info(
                "Deleting service accounts/role/rolebinding "
                + "for %s" % namespace
            )
            self.parent.rbac_api.delete_namespaced_role_binding(
                account, namespace, dopts
            )
            self.parent.rbac_api.delete_namespaced_role(
                account, namespace, dopts
            )
            self.parent.api.delete_namespaced_service_account(
                account, namespace, dopts
            )

    def dump(self):
        """Return dict for pretty-printing.
        """
        nd = {
            "namespace": self.namespace,
            "service_account": self.service_account,
            "parent": str(self.parent),
        }
        return nd

    def toJSON(self):
        return json.dumps(self.dump())
