"""
By analogy with Kubespawner, helper methods for generating K8s API objects
"""

from kubernetes.client.models import (
    V1Container,
    V1SecurityContext
)


def _create_multus_init_container(image="lsstit/ddsnet4u:latest"):
    """Create the privileged container to allow CNI bridging for DDS
    multicast.
    """
    return V1Container(
        name="multus-init",
        security_context=V1SecurityContext(
            privileged=True),
        image=image
    )
