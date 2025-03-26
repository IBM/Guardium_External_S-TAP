To use the helm charts, please edit the overrides_example.yaml file and
set the appropriate parameters for your deployment.  All the required
parameters are marked with a preceding "Required" comment.  At a minimum,
the parameters to specify the DB endpoint and the collector need to be
changed in order to be useful.

Installation can be performed by...
helm install -f overrides_example.yaml estap ./estap

Uninstall can be performed by...
helm delete estap ./estap

Upgrade can be performed by...
helm upgrade estap ./estap

Certificates can be regenerated (while keeping the same CA) with...
helm upgrade --set updateSecret=true estap ./estap

Note: The charts are also available at icr.io/guardium-insights/guardium_external_s-tap:charts_master
If you cannot pull from github but can pull images from icr.io, pull that image
and create a container (it's a scratch image, it will not run).  Once the pod is created, copy charts.tgz from the pod and extract them
```
podman create --name estap-charts icr.io/guardium-insights/guardium_external_s-tap:charts_master
podman cp estap-charts:/charts.tgz .
podman rm -f estap-charts
tar xzf charts.tgz
```
