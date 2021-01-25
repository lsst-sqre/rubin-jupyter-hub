"""This is a JupyterHub KubeSpawner, extended with the ability to manipulate
namespaces, and with a rubin_mgr attribute.
"""
import json
from .. import RubinMiddleManager
from rubin_jupyter_utils.config import RubinConfig
from rubin_jupyter_utils.helpers import (
    make_logger,
    sanitize_dict,
    assemble_gids,
    get_supplemental_gids,
)
from .multispawner import MultiNamespacedKubeSpawner
from .objects import _create_multus_init_container
from eliot import start_action
from kubespawner.objects import make_pod
from tornado import gen
from traitlets import Bool


class RubinSpawner(MultiNamespacedKubeSpawner):
    """This, plus the Rubin Manager class structure, implements the
    Rubin-specific parts of our spawning requirements.
    """

    delete_namespace_on_stop = Bool(
        True,
        config=True,
        help="""
        If True, the entire namespace will be deleted when the lab pod stops.
        """,
    ).tag(config=True)

    enable_namespace_quotas = Bool(
        True,
        config=True,
        help="""
        If True, will create a ResourceQuota object by calling
        `self.quota_mgr.get_resource_quota_spec()` and create a quota with
        the resulting specification within the namespace.

        A subclass should override the quota manager's
        define_resource_quota_spec() to build a
        situationally-appropriate resource quota spec.
        """,
    ).tag(config=True)

    def __init__(self, *args, **kwargs):
        self.log = make_logger()
        super().__init__(*args, **kwargs)
        self.log.debug("Creating RubinSpawner.")
        # Our API and our RBAC API are set in the super() __init__()
        # We want our own Rubin Manager per spawner.
        user = self.user
        if not user:
            self.log.error("No user found!")
            raise RuntimeError("Could not create spawner!")
        auth = user.authenticator
        if not auth:
            self.log.error("No authenticator found!")
            raise RuntimeError("Could not create spawner!")
        self.log.debug("Creating Rubin Manager from authenticated user.")
        self.rubin_mgr = RubinMiddleManager(
            parent=self,
            authenticator=auth,
            spawner=self,
            user=user,
            config=RubinConfig(),
        )
        self.log.debug("Initialized {}".format(__name__))
        self.cached_auth_state = {}
        self.delete_grace_period = 5
        # In the Rubin setup, there is a "provisionator" user, uid/gid 769,
        #  that is who we should start as, unless we are running sudoless.
        # If we are, we set the uid/gid/supplemental gids accordingly.
        self.uid = 769
        self.gid = 769
        self.supplemental_gids = []
        # The fields need to be defined; we don't use them.
        self.fs_gid = None
        self.extra_labels = {}
        self.extra_annotations = {}
        self.image_pull_secrets = None
        self.privileged = False
        self.working_dir = None
        self.lifecycle_hooks = {}  # This one will be useful someday.
        self.init_containers = []
        self.lab_service_account = None
        self.extra_container_config = {}
        self.extra_pod_config = {}
        self.extra_containers = []

    def auth_state_hook(self, spawner, auth_state):
        # Turns out this is in the wrong place.  It should be called
        #  _before_ get_options_form()
        self.log.debug("{} auth_state_hook firing.".format(__name__))
        self.log.debug(
            "User name in auth_state_hook is '{}'.".format(self._log_name)
        )
        if hasattr(super(), "auth_state_hook") and super().auth_state_hook:
            super().auth_state_hook(spawner, auth_state)
        else:
            self.log.debug("No superclass auth_state_hook to call.")
        self.log.debug("Updating cached auth_state.")
        self.cached_auth_state = auth_state

    @gen.coroutine
    def get_options_form(self):
        """Present a Rubin-tailored options form; delegate to options
        form manager.

        This really is stuff that should get set from auth_state_hook...
        But as it happens, that doesn't run until after get_options_form.
        """
        # If this is run with start_action from eliot, you get an error that
        #  the token was created in a different context.
        # I suspect this to be somewhere near the heart of our concurrency
        #  problems.
        self.log.debug("Entering get_options_form()")
        self.log.debug(
            "User name in get_options_form is '{}'.".format(self._log_name)
        )
        lm = self.rubin_mgr
        # Take the APIs from the api_manager
        self.api = lm.api_mgr.api
        self.rbac_api = lm.api_mgr.rbac_api
        om = lm.optionsform_mgr
        self.log.debug("Requesting auth state")
        user = self.user
        auth_state = self.cached_auth_state
        if not auth_state:
            self.log.info("No cached_auth_state(); reacquiring.")
            auth_state = yield user.get_auth_state()
            self.cached_auth_state = auth_state
        if not auth_state:
            raise ValueError("Auth state empty for user {}".format(self.user))
        uid = auth_state.get("uid")
        if not uid:
            self.log.warning(
                "auth_state does not have 'uid'.  Attempting refresh."
            )
            auth_state = yield user.authenticator.refresh_user(user, None)
            uid = auth_state.get("uid")
            if not uid:
                errstr = "auth_state does not have field 'uid'!"
                self.log.error(errstr)
                raise RuntimeError(errstr)
        self.log.debug("Requesting options_form from manager.")
        form = yield self.asynchronize(om.get_options_form)
        return form

    def set_user_namespace(self):
        """Get namespace and store it here (for spawning) and in
        namespace_mgr."""
        with start_action(action_type="set_user_namespace"):
            ns = self.get_user_namespace()
            self.namespace = ns
            self.rubin_mgr.namespace_mgr.set_namespace(ns)

    def get_user_namespace(self):
        """Return namespace for user pods (and ancillary objects).
        """
        with start_action(action_type="get_user_namespace"):
            defname = self._namespace_default()
            # We concatenate the default namespace and the name so that we
            #  can continue having multiple Jupyter instances in the same
            #  k8s cluster in different namespaces.  The user namespaces must
            #  themselves be namespaced, as it were.
            if defname == "default":
                raise ValueError("Won't spawn into default namespace!")
            return "{}-{}".format(defname, self.user.escaped_name)

    def start(self):
        """Thin wrapper around self._start

        so we can hold onto a reference for the Future
        start returns, which we can use to terminate
        .progress()
        """
        self._start_future = self._start()
        return self._start_future

    @gen.coroutine
    def _start(self):
        # Update our cached auth state on every _start call
        ast = yield self.user.get_auth_state()
        self.cached_auth_state = ast
        self.log.debug("Refreshed cached_auth_state in _start().")
        retval = yield super()._start()
        return retval

    @gen.coroutine
    def stop(self, now=False):
        """After stopping pod, delete the namespace if that option is set.
        """
        with start_action(action_type="rubinspawner_stop"):
            deleteme = self.delete_namespace_on_stop
            self.log.debug("Attempting to stop user pod.")
            self.log.debug(
                "User name in stop() is '{}'.".format(self._log_name)
            )
            self.log.debug("delete_namespace_on_stop is {}".format(deleteme))
            try:
                _ = yield super().stop(now)
            except TimeoutError:
                self.log.warning("Pod timed out waiting to stop.")
            except Exception as err:
                self.log.error("Got unexpected exception {}".format(err))
            if deleteme:
                nsm = self.rubin_mgr.namespace_mgr
                self.log.debug("Attempting to delete namespace.")
                if not nsm.namespace:
                    self.log.warning("Manager namespace fixup needed.")
                    self.set_user_namespace()
                self.asynchronize(nsm.maybe_delete_namespace)
            else:
                self.log.debug("'delete_namespace_on_stop' not set.")

    def options_from_form(self, formdata=None):
        """Delegate to form manager.
        """
        with start_action(action_type="options_from_form"):
            return self.rubin_mgr.optionsform_mgr.options_from_form(formdata)

    @gen.coroutine
    def _get_user_env(self):
        # Get authentication-session-specific variables for the pod env
        ast = self.cached_auth_state
        # Crash if any of this isn't set
        uid = ast["uid"]
        claims = ast["claims"]
        token = ast["access_token"]
        user_env = {}
        user_env["ACCESS_TOKEN"] = token
        user_env["EXTERNAL_UID"] = uid
        strict_ldap = self.rubin_mgr.config.strict_ldap_groups
        user_env["EXTERNAL_GROUPS"] = assemble_gids(claims, strict_ldap)
        email = claims.get("email") or ""
        user_env["GITHUB_EMAIL"] = email
        return user_env

    @gen.coroutine
    def get_pod_manifest(self):
        # Extend pod manifest.  This is a monster method.
        # Run the superclass version, and then extract the fields
        self.log.debug("Creating pod manifest.")
        self.log.debug(
            "User name in get_pod_manifest is '{}'.".format(self._log_name)
        )
        orig_pod = yield super().get_pod_manifest()
        labels = orig_pod.metadata.labels.copy()
        annotations = orig_pod.metadata.annotations.copy()
        ctrs = orig_pod.spec.containers
        cmd = None
        if ctrs and len(ctrs) > 0:
            cmd = ctrs[0].args or ctrs[0].command
        # That should be it from the standard get_pod_manifest
        # We assume that self.cached_auth_state is populated by the time
        #  we get here.
        # Now we finally need all that data we have been managing.
        # Add label and annotations for ArgoCD management.
        labels["argocd.argoproj.io/instance"] = "nublado-users"
        annotations["argocd.argoproj.io/compare-options"] = "IgnoreExtraneous"
        annotations["argocd.argoproj.io/sync-options"] = "Prune=false"
        cfg = self.rubin_mgr.config
        em = self.rubin_mgr.env_mgr
        nm = self.rubin_mgr.namespace_mgr
        vm = self.rubin_mgr.volume_mgr
        om = self.rubin_mgr.optionsform_mgr
        # Get the standard env and then update it with the environment
        # from our environment manager, except that we want the tokens from
        # the standard env
        tokens = {}
        pod_env = self.get_env()
        for fld in ["JUPYTERHUB_API_TOKEN", "JPY_API_TOKEN"]:
            val = pod_env.get(fld)
            if val:
                tokens[fld] = val
        em.create_pod_env()
        pod_env.update(em.get_env())
        pod_env.update(tokens)
        # And now glue in environment information that's user-specific.
        user_env = yield self._get_user_env()
        pod_env.update(user_env)
        # Set some constants
        # First pulls can be really slow for the Rubin stack containers,
        #  so let's give it a big timeout (this is in seconds)
        self.http_timeout = 60 * 15
        self.start_timeout = 60 * 15
        # We are running the Lab at the far end, not the old Notebook
        self.default_url = "/lab"
        # We always want to check for refreshed images.
        self.image_pull_policy = "Always"
        # Get image name
        pod_name = self.pod_name
        # Get default image name; we will try to replace from options form.
        image = self.image or self.orig_pod.image or cfg.lab_default_image
        # Same with tag.
        tag = "latest"
        # Parse options form result.
        size = None
        image_size = None
        clear_dotlocal = False
        if not self.user_options:
            raise ValueError("No options form data!")
        self.log.debug(
            "User options from form:\n"
            + json.dumps(self.user_options, sort_keys=True, indent=4)
        )
        size = self.user_options.get("size")
        if not size:
            # Use the deployment defaults
            size_idx = cfg.size_index
            size = cfg.form_sizelist[size_idx]
        image_size = om.sizemap[size]
        self.log.debug(
            "Image size: {}".format(
                json.dumps(image_size, sort_keys=True, indent=4)
            )
        )
        mem_limit = image_size["mem"]
        cpu_limit = image_size["cpu"]
        mem_guar = image_size["mem_guar"]
        cpu_guar = image_size["cpu_guar"]
        self.mem_guarantee = mem_guar
        self.cpu_guarantee = cpu_guar
        pod_env["MEM_GUARANTEE"] = mem_guar
        pod_env["MEM_LIMIT"] = mem_limit
        pod_env["CPU_GUARANTEE"] = str(cpu_guar)
        pod_env["CPU_LIMIT"] = str(cpu_limit)
        if self.user_options.get("kernel_image"):
            image = self.user_options.get("kernel_image")
            colon = image.find(":")
            if colon > -1:
                imgname = image[:colon]
                tag = image[(colon + 1):]
                if tag == "recommended" or tag.startswith("latest"):
                    # Resolve convenience tags to real build tags.
                    self.log.debug("Resolving tag '{}'".format(tag))
                    qtag = om.resolve_tag(tag)
                    if qtag:
                        tag = qtag
                        image = imgname + ":" + tag
                    else:
                        self.log.warning(
                            "Failed to resolve tag '{}'".format(tag)
                        )
                        self.log.debug(
                            "Image name: %s ; tag: %s" % (imgname, tag)
                        )
                if tag == "__custom":
                    self.log.debug(
                        "Tag is __custom: retrieving real "
                        + "value from drop-down list."
                    )
                    cit = self.user_options.get("image_tag")
                    if cit:
                        tag = cit
                        image = imgname + ":" + cit
            self.log.debug("Replacing image from options form: %s" % image)

            if cfg.lab_repo_host == "hub.docker.com":
                self.image = image
            else:
                self.image = cfg.lab_repo_host + "/" + image
            pod_env["JUPYTER_IMAGE_SPEC"] = image
            pod_env["JUPYTER_IMAGE"] = image
        # Set flag to clear .local if indicated
        clear_dotlocal = self.user_options.get("clear_dotlocal")
        if clear_dotlocal:
            pod_env["CLEAR_DOTLOCAL"] = "TRUE"
        # Set flag to enable debug logging in container if indicated
        enable_debug = self.user_options.get("enable_debug")
        if enable_debug:
            pod_env["DEBUG"] = "TRUE"
        # Set up Lab pod resource constraints (not namespace quotas)
        # These are the defaults from the config
        # We don't care about the image name anymore: the user pod will
        #  be named "nb" plus the username and tag, to keep the pod name
        #  short.
        rt_tag = tag.replace("_", "-")
        pn_template = "nb-{username}-" + rt_tag
        pod_name = self._expand_user_properties(pn_template)
        self.pod_name = pod_name
        self.log.debug("Replacing pod name from options form: %s" % pod_name)
        # Get quota definitions from quota manager.
        if self.enable_namespace_quotas:
            qmq = self.rubin_mgr.quota_mgr.quota
            if qmq:
                if "limits.cpu" in qmq:
                    pod_env["NAMESPACE_CPU_LIMIT"] = qmq["limits.cpu"]
                if "limits.memory" in qmq:
                    nmlimit = qmq["limits.memory"]
                    if nmlimit[-2:] == "Mi":
                        nmlimit = nmlimit[:-2] + "M"
                    pod_env["NAMESPACE_MEM_LIMIT"] = nmlimit
        # Get volume definitions from volume manager.
        vm.make_volumes_from_config()
        pod_env["DASK_VOLUME_B64"] = vm.get_dask_volume_b64()
        self.volumes = vm.k8s_volumes
        self.volume_mounts = vm.k8s_vol_mts
        # Add SAL-specific settings
        # Add multus annotations if requested
        if cfg.enable_multus:
            annotations.update(cfg.multus_annotation)
            self.init_containers.append(_create_multus_init_container(
                cfg.multus_init_container_image))
        if cfg.lab_dds_interface:
            pod_env["LSST_DDS_INTERFACE"] = cfg.lab_dds_interface
        if cfg.lab_dds_domain:
            pod_env["LSST_DDS_DOMAIN"] = cfg.lab_dds_domain
        if cfg.lab_dds_partition_prefix:
            pod_env["LSST_DDS_PARTITION_PREFIX"] = cfg.lab_dds_partition_prefix
        # Generate the pod definition.
        sanitized_env = sanitize_dict(
            pod_env,
            [
                "ACCESS_TOKEN",
                "GITHUB_ACCESS_TOKEN",
                "JUPYTERHUB_API_TOKEN",
                "JPY_API_TOKEN",
            ],
        )
        # Check to see if we're running without sudo
        if cfg.lab_no_sudo:
            pod_env["NO_SUDO"] = "TRUE"
            ast = self.cached_auth_state
            uid = int(ast["uid"])
            self.uid = uid  # Run directly as user
            self.gid = uid  # (with private group)
            claims = ast["claims"]
            strict_ldap = self.rubin_mgr.config.strict_ldap_groups
            self.supplemental_gids = get_supplemental_gids(claims, strict_ldap)
        self.set_user_namespace()
        daskconfig = None
        if cfg.allow_dask_spawn:
            ast = self.cached_auth_state
            daskconfig = {
                "debug": enable_debug,
                "image": self.image,
                "instance_name": cfg.instance_name,
                "resources": {
                    "limits": {
                        "cpu": pod_env["CPU_LIMIT"],
                        "memory": pod_env["MEM_LIMIT"],
                    },
                    "requests": {
                        "cpu": pod_env["CPU_GUARANTEE"],
                        "memory": pod_env["MEM_GUARANTEE"],
                    },
                },
                "auth_state": ast,
            }
        self.log.debug(
            "Pod environment: {}".format(
                json.dumps(sanitized_env, sort_keys=True, indent=4)
            )
        )
        # This is the part that actually makes the K8s resources.
        nm.ensure_namespace(namespace=self.namespace, daskconfig=daskconfig)
        # If we can spawn other pods from the Lab, we need a svcaccount,
        #  which we just created in the namespace resources.
        self.lab_service_account = nm.service_account
        self.log.debug("About to run make_pod()")
        pod = make_pod(
            name=self.pod_name,
            cmd=cmd,
            port=self.port,
            image=self.image,
            image_pull_policy=self.image_pull_policy,
            image_pull_secret=self.image_pull_secrets,
            node_selector=self.node_selector,
            run_as_uid=self.uid,
            run_as_gid=self.gid,
            fs_gid=self.fs_gid,
            supplemental_gids=self.supplemental_gids,
            run_privileged=self.privileged,
            env=pod_env,
            volumes=self._expand_all(self.volumes),
            volume_mounts=self._expand_all(self.volume_mounts),
            working_dir=self.working_dir,
            labels=labels,
            annotations=annotations,
            cpu_limit=self.cpu_limit,
            cpu_guarantee=self.cpu_guarantee,
            mem_limit=self.mem_limit,
            mem_guarantee=self.mem_guarantee,
            extra_resource_limits=self.extra_resource_limits,
            extra_resource_guarantees=self.extra_resource_guarantees,
            lifecycle_hooks=self.lifecycle_hooks,
            init_containers=self._expand_all(self.init_containers),
            service_account=self.lab_service_account,
            extra_container_config=self.extra_container_config,
            extra_pod_config=self.extra_pod_config,
            extra_containers=self.extra_containers,
            node_affinity_preferred=self.node_affinity_preferred,
            node_affinity_required=self.node_affinity_required,
            pod_affinity_preferred=self.pod_affinity_preferred,
            pod_affinity_required=self.pod_affinity_required,
            pod_anti_affinity_preferred=self.pod_anti_affinity_preferred,
            pod_anti_affinity_required=self.pod_anti_affinity_required,
            priority_class_name=self.priority_class_name,
            logger=self.log,
        )
        return pod

    def dump(self):
        """Return dict representation suitable for pretty-printing."""
        sd = {
            "namespace": self.namespace,
            "uid": self.uid,
            "gid": self.gid,
            "fs_gid": self.fs_gid,
            "supplemental_gids": self.supplemental_gids,
            "extra_labels": self.extra_labels,
            "extra_annotations": self.extra_annotations,
            "delete_grace_period": self.delete_grace_period,
            "privileged": self.privileged,
            "working_dir": self.working_dir,
            "lifecycle_hooks": self.lifecycle_hooks,
            "init_containers": self.init_containers,
            "lab_service_account": self.lab_service_account,
            "extra_container_config": self.extra_container_config,
            "extra_pod_config": self.extra_pod_config,
            "extra_containers": self.extra_containers,
            "delete_namespace_on_stop": self.delete_namespace_on_stop,
            "enable_namespace_quotas": self.enable_namespace_quotas,
            "rubin_mgr": self.rubin_mgr.dump(),
        }
        return sd

    def toJSON(self):
        return json.dumps(self.dump())
