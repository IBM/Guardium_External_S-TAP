To deploy External S-TAP to a namespace where you do not have sufficient
permission to GET, CREATE, or UPDATE serviceAccount, role, or roleBinding
objects, you will need to have an administrator create the following
objects for you (with the correct namespace) in order to have the
deployment create the secret containing default certificates for you.

```
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: estap-secret-writer
  labels:
    app.kubernetes.io/component: estap
    app.kubernetes.io/part-of: estap
    app.kubernetes.io/managed-by: Helm
  annotations:
    meta.helm.sh/release-name: estap
    meta.helm.sh/release-namespace: YOUR_NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: estap-secret-writer-role
  labels:
    app.kubernetes.io/component: estap
    app.kubernetes.io/part-of: estap
    app.kubernetes.io/managed-by: Helm
  annotations:
    meta.helm.sh/release-name: estap
    meta.helm.sh/release-name: YOUR_NAMESPACE
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "watch", "list", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: estap-secret-writer-rolebinding
  labels:
    app.kubernetes.io/component: estap
    app.kubernetes.io/part-of: estap
    app.kubernetes.io/managed-by: Helm
  annotations:
    meta.helm.sh/release-name: estap
    meta.helm.sh/release-namespace: YOUR_NAMESPACE
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: estap-secret-writer-role
subjects:
  - kind: ServiceAccount
    name: estap-secret-writer
```

If you are unable to get a serviceAccount in order to automatically
deploy the secrets but prefer to have the default secret created
instead of manually creating one with certificates inside, with 
the above serviceAccount and RBAC, you can have an administrator
create the default secret with the following yaml as an example,
noting that the seviceAccountName and image may be different
for you.  The name of the secret created is in the args line 
of the container estap-create-secret-job and, in this example, is
'estap-secret'.  If the secret needs to be created in another
namespace, use the kubectl option --namespace parameter.

```
kind: Job
apiVersion: batch/v1
metadata:
  name: estap-create-secret-job
  labels:
    app.kubernetes.io/name: estap
    app.kubernetes.io/component: estap
    app.kubernetes.io/part-of: estap
spec:
    template:
      metadata:
        labels:
          run: estap-create-secret-job
      spec:
        volumes:
        - emptyDir: {}
          name: metastore-volume
        serviceAccountName: estap-secret-writer
        initContainers:
        - name: estap-create-secret-job-cert-gen
          volumeMounts:
          - mountPath: /tmp/metastore
            name: metastore-volume
          image: icr.io/guardium-insights/guardium_external_s-tap:v12.1
          args: ['gpctl genca > /tmp/metastore/ca.pem && gpctl gen_csr && mv /var/log/gp/key.tmp.pem /tmp/metastore/tls.key && gpctl -A/tmp/metastore/ca.pem -R/var/log/gp/csr.tmp.pem sign_csr > /tmp/metastore/tls.crt && rm -f /var/log/gp/csr.tmp.pem' ]
          command:
          - /bin/sh
          - '-c'
          imagePullPolicy: IfNotPresent
        containers:
        - name: estap-create-secret-job
          volumeMounts:
          - mountPath: /tmp/metastore
            name: metastore-volume
          image: icr.io/guardium-insights/guardium_external_s-tap:v12.1
          args: ["env && kubectl create secret generic estap-secret --from-file=ca.pem=/tmp/metastore/ca.pem --from-file=tls.key=/tmp/metastore/tls.key --from-file=tls.crt=/tmp/metastore/tls.crt"]
          command:
          - /bin/sh
          - '-c'
          imagePullPolicy: IfNotPresent
        restartPolicy: OnFailure
```
