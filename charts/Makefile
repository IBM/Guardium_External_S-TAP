PACKAGE_FILES := estap/Chart.yaml \
./estap/templates/_helpers.tpl \
./estap/templates/default-networkpolicy.yaml \
./estap/templates/estap-configmap.yaml \
./estap/templates/estap-create-default-secret.yaml \
./estap/templates/estap-deploy.yaml \
./estap/templates/estap-networkpolicy.yaml \
./estap/templates/estap-service.yaml \
./estap/templates/post-install.yaml \
./estap/templates/estap-create-secret-writer-role.yaml \
./estap/templates/estap-create-secret-writer-rolebinding.yaml \
./estap/templates/estap-create-secret-writer-serviceaccount.yaml \
./estap/values.yaml \
./estap/.helmignore \
./README.md \
./RBAC_example.md \
./overrides_example.yaml

charts.tgz: $(PACKAGE_FILES)
	tar czf charts.tgz $(PACKAGE_FILES)

.phony: clean

clean:
	rm -f charts.tgz

image: Dockerfile charts.tgz
	podman build -t guardium_external_s-tap:charts_`git branch --show-current` .
