# vim: ts=2:sw=2:et

{{- define "common.labels" }}
chart: "{{ .Chart.Name }}"
heritage: {{ .Release.Service }}
release: {{ .Release.Name }}
app.kubernetes.io/name: {{ .Chart.Name }}
helm.sh/chart: {{ .Chart.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .Values.estap.name | default "estap" }}
app.kubernetes.io/part-of: {{ .Values.estap.name | default "estap" }}
{{- end }}

{{- define "common.name" }}
{{- if .Values.estap.name }}
{{- printf "%s-%s" .Values.estap.name .Release.Name | trunc 48 | trimSuffix "-" -}}
{{- else }}
{{- printf "estap-%s" .Release.Name | trunc 48 | trimSuffix "-" -}}
{{- end }}
{{- end }}

{{- define "estap-deploy.estap.serviceAccountName" }}
{{- .Values.estap.serviceAccountName | default "default" }}
{{- end }}

{{- define "estap-deploy.estap.uid" }}
{{- .Values.estap.uid | default 1000 }}
{{- end }}

{{- define "estap-deploy.estap.fsGroup" }}
{{- .Values.estap.fsGroup | default 1000 }}
{{- end }}

{{- define "estap-deploy.estap.supplementalGroups" }}
{{- include "estap-deploy.estap.fsGroup" . -}}{{- if (ne (int .Values.estap.uid | default 1000) 1000) -}}, 0{{- end -}}{{- if .Values.estap.supplementalGroups -}}, {{ .Values.estap.supplementalGroups }}{{- end -}}
{{- end }}

{{- define "estap-deploy.estap.registryImageTag" }}
{{- if .Values.global }}
{{- $prefix := .Values.global.dockerRegistryPrefix | default "docker.io/ibmcom/" | trimSuffix "/" }}
{{- $image := .Values.global.image | default "guardium_external_s-tap" }}
{{- $tag := .Values.global.tag | default "v11.3.0" }}
{{- printf "%s/%s:%s" $prefix $image $tag }}
{{- else }}
{{- printf "docker.io/ibmcom/guardium_external_s-tap:v11.3.0" }}
{{- end }}
{{- end }}

{{- define "estap-deploy.container.securityContext" }}
allowPrivilegeEscalation: false
capabilities:
  drop:
  - ALL
privileged: false
readOnlyRootFilesystem: true
{{- end }}

{{- define "estap-deploy.estap.imagePullPolicy" }}
{{- $defaultPolicy := "IfNotPresent" }}
{{- if .Values.global }}
{{- .Values.global.imagePullPolicy | default $defaultPolicy }}
{{- else }}
{{- printf "%s" $defaultPolicy }}
{{- end }}
{{- end }}

{{- define "estap-deploy.estap.livenessProbe.command" }}
{{- .Values.estap.livenessProbe.command | default "/usr/sbin/gproxy_live" | quote }}
{{- end }}

{{- define "estap-deploy.estap.livenessProbe.periodSeconds" }}
{{- .Values.estap.livenessProbe.periodSeconds | default 10 }}
{{- end }}

{{- define "estap-deploy.estap.livenessProbe.failureThreshold" }}
{{- .Values.estap.livenessProbe.failureThreshold | default 4 }}
{{- end }}

{{- define "estap-deploy.estap.livenessProbe.initialDelaySeconds" }}
{{- .Values.estap.livenessProbe.initialDelaySeconds | default 0 }}
{{- end }}

{{- define "estap-deploy.estap.readinessProbe.command" }}
{{- .Values.estap.readinessProbe.command | default "/usr/sbin/gproxy_ready" | quote }}
{{- end }}

{{- define "estap-deploy.estap.readinessProbe.periodSeconds" }}
{{- .Values.estap.readinessProbe.periodSeconds | default 5 }}
{{- end }}

{{- define "estap-deploy.estap.readinessProbe.failureThreshold" }}
{{- .Values.estap.readinessProbe.failureThreshold | default 5 }}
{{- end }}

{{- define "estap-deploy.estap.readinessProbe.initialDelaySeconds" }}
{{- .Values.estap.readinessProbe.initialDelaySeconds | default 0 }}
{{- end }}

{{- define "estap-deploy.estap.participate_in_load_balancing" }}
{{- .Values.estap.participate_in_load_balancing | default 0 }}
{{- end }}

{{- define "estap-deploy.estap.replicas" }}
{{- .Values.estap.replicas | default 2 }}
{{- end }}

{{- define "estap-deploy.estap.verify_guardium.ca_path" }}
{{- .Values.estap.verify_guardium.ca_path | default "/etc/guardium/guardium_ca.crt" }}
{{- end }}

{{- define "estap-deploy.estap.proxy.debug" }}
{{- if .Values.estap.proxy }}{{ .Values.estap.proxy.debug | default 0 }}{{- else }}0{{- end }}
{{- end }}

{{- define "estap-deploy.estap.proxy.num_workers" }}
{{- if .Values.estap.proxy }}{{ .Values.estap.proxy.num_workers | default 1 }}{{- else }}1{{- end }}
{{- end }}

{{- define "estap-deploy.estap.proxy.proxy_protocol" }}
{{- if .Values.estap.proxy }}{{ .Values.estap.proxy.proxy_protocol | default 0 }}{{- else }}0{{- end }}
{{- end }}

{{- define "estap-deploy.estap.proxy.disconnect_on_invalid_certificate" }}
{{- if .Values.estap.proxy }}{{- if .Values.estap.proxy.disconnect_on_invalid_certificate }}1{{- else }}0{{- end }}{{- else }}0{{- end }}
{{- end }}

{{- define "estap-deploy.estap.proxy.notify_on_invalid_certificate" }}
{{- if .Values.estap.proxy }}{{- if .Values.estap.proxy.notify_on_invalid_certificate }}1{{- else }}0{{- end }}{{- else }}0{{- end }}
{{- end }}

{{- define "estap-deploy.estap.proxy.listen_port" }}
{{- if .Values.estap.proxy }}{{ .Values.estap.proxy.listen_port | default 8888 }}{{- else }}8888{{- end }}
{{- end }}

{{- define "estap-deploy.estap.db.port" }}
{{- .Values.estap.db.port | default 50000 }}
{{- end }}

{{- define "estap-deploy.estap.requests.cpu" }}
{{- if .Values.estap.requests }}{{- .Values.estap.requests.cpu | default "100m" }}{{- else }}"100m"{{- end }}
{{- end }}

{{- define "estap-deploy.estap.requests.memory" }}
{{- if .Values.estap.requests }}{{- .Values.estap.requests.memory | default "512Mi" }}{{- else }}"512Mi"{{- end }}
{{- end }}

{{- define "estap-deploy.estap.limits.cpu" }}
{{- if .Values.estap.limits }}{{ .Values.estap.limits.cpu | default "500m" }}{{- else }}"500m"{{- end }}
{{- end }}

{{- define "estap-deploy.estap.limits.memory" }}
{{- if .Values.estap.limits }}{{ .Values.estap.limits.memory | default "756Mi" }}{{- else }}"756Mi"{{- end }}
{{- end }}

{{- define "estap-deploy.global.secretWriterServiceAccountName" }}
{{- .Values.global.secretWriterServiceAccountName | default "estap-secret-writer" }}
{{- end }}
