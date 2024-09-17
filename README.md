# compliance-operator

[![Join the chat at https://gitter.im/Compliance-As-Code-The/compliance-operator](https://badges.gitter.im/Compliance-As-Code-The/compliance-operator.svg)](https://gitter.im/Compliance-As-Code-The/compliance-operator?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

The compliance-operator is a OpenShift Operator that allows an administrator
to run compliance scans and provide remediations for the issues found. The
operator leverages OpenSCAP under the hood to perform the scans.

## Table of Contents

[Installation Guide](doc/install.md)

[Usage Guide](doc/usage.md)

[Contributor Guide](doc/contributor.md)




# CEL scanner guide

**Features Supported with this branch:**
- **CEL Platform Rule Support**:
  - A `ComplianceRule` object based on CEL can be created manually.
  - A `TailoredProfile` can be created that selects the CEL rule.
  - The `ScanSettingBinding` controller can recognize the `TailoredProfile` with the CEL scanner type and create a scan configuration for it.
  - The `ComplianceScan` controller recognizes the CEL scanner type and launches the corresponding `api-resource-collector` and `cel-scanner` accordingly.
  - The `api-resource-collector` identifies the `TailoredProfile` with CEL rules, fetches resources for all the CEL rules, and dumps them into a directory.
  - The CEL scanner then takes the fetched API resource directory, scans the resources against the CEL rules selected in the `TailoredProfile`, and saves the results in a file within the container.
  - The `log-collector` will pick up the file, and create a configmap contins result list
  - The `aggregator` will be able parse the result configmap and create the CCR
  - TailoredProfile is allowed to not have a `Profile` or `ProfileBundle` owner, so it is possible to create custom rule
  - Ported in PR#590 Optional storage, since CEL scanner will not generate ARF report.
  - Removed `Subresource` field from the original POC, `Subresource` can be referenced using `/` in the `Resource` field

**Missing Features:**
- **Importing CEL Rules to the Operator**:
  - We need to implement a method to import CEL rules directly into the operator.
- **Node Scanning Support**:
  - Extend support to include node-level scanning.
- **Rule Remediations**:
  - Need to support remediations, missing remediation information

**How to Test the Feature:**
- Create a CEL rule and a `TailoredProfile` that selects the CEL rule.
- Create a `ScanSettingBinding` that selects the `TailoredProfile` to launch the scan.

The demo files can be found under `hack/cel-rule.yaml`

Run `oc apply -f hack/cel-rule.yaml` to test the feature.


## Example output
```
vincent@node:~/ws-compliance/compliance-operator$ oc get pod -w
NAME                                             READY   STATUS            RESTARTS   AGE
cel-scanner-tp-api-checks-pod                    0/2     PodInitializing   0          4s
compliance-operator-cc7c9989-x8dxs               1/1     Running           0          9s
compliance-operator-cc7c9989-z2dvr               1/1     Terminating       0          4m19s
ocp4-openshift-compliance-pp-665fcbc659-xjd5f    1/1     Running           0          50m
rhcos4-openshift-compliance-pp-d4b49bcbf-gp9wd   1/1     Running           0          50m
cel-scanner-tp-api-checks-pod                    0/2     Completed         0          4s
cel-scanner-tp-api-checks-pod                    0/2     Completed         0          6s
aggregator-pod-cel-scanner-tp                    0/1     Pending           0          0s
aggregator-pod-cel-scanner-tp                    0/1     Pending           0          0s
aggregator-pod-cel-scanner-tp                    0/1     Pending           0          0s
aggregator-pod-cel-scanner-tp                    0/1     Init:0/1          0          0s
aggregator-pod-cel-scanner-tp                    0/1     Init:0/1          0          1s
aggregator-pod-cel-scanner-tp                    0/1     PodInitializing   0          2s
aggregator-pod-cel-scanner-tp                    0/1     Completed         0          4s
aggregator-pod-cel-scanner-tp                    0/1     Completed         0          6s
^Cvincent@node:~/ws-compliance/compliance-operator$ oc get ccr
NAME                                                   STATUS   SEVERITY
cel-scanner-tp-configure-network-policies-namespaces   FAIL     high
cel-scanner-tp-etcd-cert-file                          PASS     medium
vincent@node:~/ws-compliance/compliance-operator$ oc get ccr -o yaml
apiVersion: v1
items:
- apiVersion: compliance.openshift.io/v1alpha1
  description: Use network policies to isolate traffic in your cluster network.
  id: xccdf_org.ssgproject.content_rule_configure_network_policies_namespaces
  instructions: |-
    Verify that the every non-control plane namespace has an appropriate
    NetworkPolicy.

    To get all the non-control plane namespaces, you can do the
    following command $ oc get  namespaces -o json | jq '[.items[] | select((.metadata.name | startswith("openshift") | not) and (.metadata.name | startswith("kube-") | not) and .metadata.name != "default" and (true)) | .metadata.name ]'

    To get all the non-control plane namespaces with a NetworkPolicy, you can do the
    following command $ oc get --all-namespaces networkpolicies -o json | jq '[.items[] | select((.metadata.namespace | startswith("openshift") | not) and (.metadata.namespace | startswith("kube-") | not) and .metadata.namespace != "default" and (true)) | .metadata.namespace] | unique'

    Namespaces matching the variable ocp4-var-network-policies-namespaces-exempt-regex regex are excluded from this check.

    Make sure that the namespaces displayed in the commands of the commands match.
    Is it the case that Namespaced Network Policies needs review?
  kind: ComplianceCheckResult
  metadata:
    annotations:
      compliance.openshift.io/last-scanned-timestamp: "2024-09-18T10:21:51Z"
      compliance.openshift.io/rule: configure-network-policies-namespaces
    creationTimestamp: "2024-09-18T10:22:04Z"
    generation: 1
    labels:
      compliance.openshift.io/check-severity: high
      compliance.openshift.io/check-status: FAIL
      compliance.openshift.io/profile-guid: eb69c261-e527-5a05-9814-1fb1358bcc23
      compliance.openshift.io/scan-name: cel-scanner-tp
      compliance.openshift.io/suite: cel-ssb
    name: cel-scanner-tp-configure-network-policies-namespaces
    namespace: openshift-compliance
    ownerReferences:
    - apiVersion: compliance.openshift.io/v1alpha1
      blockOwnerDeletion: true
      controller: true
      kind: ComplianceScan
      name: cel-scanner-tp
      uid: e869bfc7-837f-4cc0-942d-56826f481656
    resourceVersion: "64996"
    uid: e0ba9316-fb5a-47e8-ac97-2aff06813691
  rationale: Running different applications on the same Kubernetes cluster creates
    a risk of one compromised application attacking a neighboring application. Network
    segmentation is important to ensure that containers can communicate only with
    those they are supposed to. When a network policy is introduced to a given namespace,
    all traffic not allowed by the policy is denied. However, if there are no network
    policies in a namespace all traffic will be allowed into and out of the pods in
    that namespace.
  severity: high
  status: FAIL
  warnings:
  - ""
  - Application Namespaces do not have Network Policies defined.
- apiVersion: compliance.openshift.io/v1alpha1
  description: |-
    To ensure the etcd service is serving TLS to clients, make sure the etcd-pod* ConfigMaps in the openshift-etcd namespace contain the following argument for the etcd binary in the etcd pod:

    --cert-file=/etc/kubernetes/static-pod-certs/secrets/etcd-all-[a-z]+/etcd-serving-NODE_NAME.crt

    . Note that the

    [a-z]+

    is being used since the directory might change between OpenShift versions.
  id: xccdf_org.ssgproject.content_rule_etcd_cert_file
  instructions: |-
    Run the following command:
    oc get -nopenshift-etcd cm etcd-pod -oyaml | grep -E "\-\-cert-file=/etc/kubernetes/static-pod-certs/secrets/etcd-all-[a-z]+/etcd-serving-NODE_NAME.crt"
    Verify that there is a certificate configured.
    Is it the case that the etcd client certificate is not configure
  kind: ComplianceCheckResult
  metadata:
    annotations:
      compliance.openshift.io/last-scanned-timestamp: "2024-09-18T10:21:51Z"
      compliance.openshift.io/rule: etcd-cert-file
    creationTimestamp: "2024-09-18T10:22:04Z"
    generation: 1
    labels:
      compliance.openshift.io/check-severity: medium
      compliance.openshift.io/check-status: PASS
      compliance.openshift.io/profile-guid: eb69c261-e527-5a05-9814-1fb1358bcc23
      compliance.openshift.io/scan-name: cel-scanner-tp
      compliance.openshift.io/suite: cel-ssb
    name: cel-scanner-tp-etcd-cert-file
    namespace: openshift-compliance
    ownerReferences:
    - apiVersion: compliance.openshift.io/v1alpha1
      blockOwnerDeletion: true
      controller: true
      kind: ComplianceScan
      name: cel-scanner-tp
      uid: e869bfc7-837f-4cc0-942d-56826f481656
    resourceVersion: "64997"
    uid: d783448d-e0f9-4276-abce-7a20cae1bcba
  rationale: Without cryptographic integrity protections, information can be altered
    by unauthorized users without detection.
  severity: medium
  status: PASS
  warnings:
  - ""
  - |
    Ensure the etcd client certificate is set: true
kind: List
metadata:
  resourceVersion: ""
```

## Questions

### How Should We Import Profile Rules to the Operator? Now we rely on profilebundle to import rules through datastream file.
