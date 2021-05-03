To use the helm charts, please edit the overrides_example.yaml file and
set the appropriate parameters for your deployment.  All the required
parameters are marked with a preceding "Required" comment.  At a minimum,
the parameters to specify the DB endpoint and the collector need to be
changed in order to be useful.

Installation can be performed by...
helm install -f overrides_example.yaml estap ./estap

Uninstall can be performed by...
helm delete estap ./estap
