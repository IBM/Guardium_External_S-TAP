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
