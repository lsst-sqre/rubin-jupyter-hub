import base64
import json
import yaml
from eliot import start_action
from kubernetes import client
from .. import LoggableChild

PWFILES = ["passwd", "group", "shadow", "gshadow"]
CONFIGMAPS = PWFILES + ["mountpoints", "access-token", "dask-config"]


class RubinVolumeManager(LoggableChild):
    """Class to provide support for document-driven Volume assignment.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.volume_list = []
        self.k8s_volumes = []
        self.k8s_vol_mts = []

    def make_volumes_from_config(self):
        """Create volume definition representation from document.
        Override this in a subclass if you like.
        """
        with start_action(action_type="make_volumes_from_config"):
            vollist = []
            config = []
            config_file = self.parent.config.volume_definition_file
            if config_file:
                try:
                    with open(config_file, "r") as fp:
                        config = json.load(fp)
                except Exception as e:
                    self.log.error(
                        ("Could not read config file '{}': " + "{}").format(
                            config_file, e
                        )
                    )
            for mtpt in config:
                mountpoint = mtpt["mountpoint"]  # Fatal error if it
                # doesn't exist
                if mtpt.get("disabled"):
                    continue
                if mountpoint[0] != "/":
                    mountpoint = "/" + mountpoint
                host = (
                    mtpt.get("fileserver-host")
                    or self.parent.config.fileserver_host
                )
                export = mtpt.get("fileserver-export") or (
                    "/exports" + mountpoint
                )
                mode = (mtpt.get("mode") or "ro").lower()
                k8s_vol = mtpt.get("kubernetes-volume")
                if k8s_vol:
                    raise ValueError(
                        "Shadow PVs and matching PVCs "
                        + "are no longer supported!"
                    )
                hostpath = mtpt.get("hostpath")
                vollist.append(
                    {
                        "mountpoint": mountpoint,
                        "hostpath": hostpath,
                        "host": host,
                        "export": export,
                        "mode": mode,
                    }
                )
            self.volume_list = vollist
            self.log.debug("Volumes: {}".format(vollist))
            self._define_k8s_object_representations()

    def _define_k8s_object_representations(self):
        with start_action(action_type="_define_k8s_object_representations"):
            self.k8s_volumes = self._make_config_map_volumes()
            self.k8s_vol_mts = self._make_config_map_mtpts()
            for vol in self.volume_list:
                k8svol = None
                k8smt = None
                if vol.get("hostpath"):
                    k8svol = self._define_k8s_hostpath_vol(vol)
                else:
                    k8svol = self._define_k8s_nfs_vol(vol)
                k8smt = self._define_k8s_mtpt(vol)
                if k8svol and k8smt:
                    self.k8s_volumes.append(k8svol)
                    self.k8s_vol_mts.append(k8smt)

    def _make_config_map_volumes(self):
        cmvls = []
        for cname in CONFIGMAPS:
            if cname in PWFILES:
                # If no_sudo is *not* set, provisionator will construct
                #  the user and group entries at startup.
                if not self.parent.config.lab_no_sudo:
                    continue
            vol = client.V1Volume(
                name=cname,
                config_map=client.V1ConfigMapVolumeSource(name=cname),
            )
            if cname.endswith("shadow"):
                vol.default_mode = 0o600
            else:
                vol.default_mode = 0o444
            cmvls.append(vol)
        return cmvls

    def _make_config_map_mtpts(self):
        cmts = []
        for cname in CONFIGMAPS:
            if cname in PWFILES:
                # If no_sudo is *not* set, provisionator will construct
                #  the user and group entries at startup.
                if not self.parent.config.lab_no_sudo:
                    continue
                # password/group files go in /etc
                fpath = "/etc/{}".format(cname)
                cmts.append(
                    client.V1VolumeMount(
                        name=cname,
                        read_only=True,
                        mount_path=fpath,
                        sub_path=cname,
                    )
                )
            elif cname == "access-token":
                # We will symlink .../tokens/{instance}-token to
                #  ~/.access_token at runtime.  We don't want to use
                #  a subpath because we DO want .access_token to be
                #  updateable in a running container if we get some sort
                #  of token refresh mechanism in the future.
                mtpath = "/opt/lsst/software/jupyterhub/tokens"
                cmts.append(
                    client.V1VolumeMount(
                        name=cname, mount_path=mtpath, read_only=True
                    )
                )
            elif cname == "dask-config":
                # Same strategy as access_token
                cfg = self.parent.config
                if not cfg.allow_dask_spawn:
                    continue
                mtpath = "/opt/lsst/software/jupyterhub/dask_yaml"
                cmts.append(
                    client.V1VolumeMount(
                        name=cname, mount_path=mtpath, read_only=True
                    )
                )
            elif cname == "mountpoints":
                cmts.append(
                    client.V1VolumeMount(
                        name=cname,
                        read_only=True,
                        mount_path="/opt/lsst/software/jupyterhub/mounts",
                    )
                )
            else:
                self.log.warning("Unrecognized ConfigMap '{}'!".format(cname))
        return cmts

    def _define_k8s_hostpath_vol(self, vol):
        with start_action(action_type="_define_k8s_hostpath_vol"):
            return client.V1Volume(
                name=self._get_volume_name_for_mountpoint(vol["mountpoint"]),
                host_path=client.V1HostPathVolumeSource(path=vol["hostpath"]),
            )

    def _define_k8s_nfs_vol(self, vol):
        with start_action(action_type="_define_k8s_nfs_vol"):
            knf = client.V1NFSVolumeSource(
                path=vol["export"], server=vol["host"]
            )
            if vol["mode"] == "ro":
                knf.read_only = True
            return client.V1Volume(
                name=self._get_volume_name_for_mountpoint(vol["mountpoint"]),
                nfs=knf,
            )

    def _define_k8s_mtpt(self, vol):
        with start_action(action_type="_define_k8s_mtpt"):
            mt = client.V1VolumeMount(
                mount_path=vol["mountpoint"],
                name=self._get_volume_name_for_mountpoint(vol["mountpoint"]),
            )
            if vol["mode"] == "ro":
                mt.read_only = True
            return mt

    def _get_volume_name_for_mountpoint(self, mountpoint):
        with start_action(action_type="_get_volume_name_for_mountpoint"):
            return mountpoint[1:].replace("/", "-")

    def get_volume_list(self):
        """Get a list object suitable for yaml-encoding.
        """
        with start_action(action_type="get_volume_list"):
            vols = self.k8s_volumes
            if not vols:
                self.log.warning("No volumes defined.")
                return ""
            vl = []
            for vol in vols:
                nm = vol.name
                hp = vol.host_path
                nf = vol.nfs
                cm = vol.config_map
                vo = {"name": nm}
                if hp:
                    vo["hostPath"] = {"path": hp.path}
                    vl.append(vo)
                elif nf:
                    am = "ReadWriteMany"
                    if nf.read_only:
                        am = "ReadOnlyMany"
                    vo["nfs"] = {
                        "server": nf.server,
                        "path": nf.path,
                        "accessMode": am,
                    }
                    vl.append(vo)
                elif cm:
                    mode = 0o444
                    name = cm.name
                    if name.endswith("shadow"):
                        mode = 0o000
                    vo["configMap"] = {"name": name, "defaultMode": mode}
                    vl.append(vo)
                else:
                    self.log.warning("Could not YAMLify volume {}".format(vol))
            return vl

    def _get_volume_yaml_str(self, left_pad=0):
        with start_action(action_type="_get_volume_yaml_str"):
            vl = self.get_volume_list()
            vs = {"volumes": vl}
            ystr = yaml.dump(vs)
            return self._left_pad(ystr, left_pad)

    def get_volume_mount_list(self):
        with start_action(action_type="get_volume_mount_list"):
            vms = self.k8s_vol_mts
            if not vms:
                self.log.warning("No volume mounts defined.")
                return ""
            vl = []
            for vm in vms:
                vo = {}
                vo["name"] = vm.name
                vo["mountPath"] = vm.mount_path
                if vm.read_only:
                    vo["readOnly"] = True
                vl.append(vo)
            return vl

    def _get_volume_mount_yaml_str(self, left_pad=0):
        with start_action(action_type="_get_volume_mount_yaml_str"):
            vl = self.get_volume_mount_list()
            vs = {"volumeMounts": vl}
            ystr = yaml.dump(vs)
            return self._left_pad(ystr, left_pad)

    def _left_pad(self, line_str, left_pad=0):
        with start_action(action_type="_left_pad"):
            pad = " " * left_pad
            ylines = line_str.split("\n")
            padlines = [(pad + ln) for ln in ylines]
            return "\n".join(padlines)

    def get_dask_volume_b64(self):
        """Return the base-64 encoding of the K8s statements to create
        the pod's mountpoints.  Probably better handled as a ConfigMap.
        """
        with start_action(action_type="get_dask_volume_b64"):
            vmt_yaml_str = self._get_volume_mount_yaml_str(left_pad=4)
            vol_yaml_str = self._get_volume_yaml_str(left_pad=2)
            ystr = "{}\n{}".format(vmt_yaml_str, vol_yaml_str)
            benc = base64.b64encode(ystr.encode("utf-8")).decode("utf-8")
            return benc

    def dump(self):
        """Return contents dict for aggregation and pretty-printing.
        """
        vd = {
            "parent": str(self.parent),
            "volume_list": self.volume_list,
            "k8s_volumes": [str(x) for x in self.k8s_volumes],
            "k8s_vol_mts": [str(x) for x in self.k8s_vol_mts],
        }
        return vd

    def toJSON(self):
        return json.dumps(self.dump())
