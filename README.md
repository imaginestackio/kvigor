# KVigor aims to find various problems on Kubernetes, such as application misconfiguration, unhealthy cluster components and node problems. 

KVigor is an inspection tool for Kubernetes. It discovers whether Kubernetes resources (by using [OPA](https://github.com/open-policy-agent/opa) ), cluster components, cluster nodes (by using [Node-Problem-Detector](https://github.com/kubernetes/node-problem-detector)), and other configurations comply with best practices and makes modification suggestions accordingly.
KubeEye supports custom inspection rules and plugin installation. With [KVigor Operator](#kvigor-operator), you can intuitively view the inspection results and modification suggestions on the web console.

## Architecture
KVigor obtains cluster resource details by using Kubernetes APIs, inspects resource configurations by using inspection rules and plugins, and generates inspection results. The architecture of KVigor is as follows:



## Install and use KVigor

1. Install KVigor on your machine.

   - Method 1: Download the pre-built executable file from [Releases](https://github.com/imaginekube/kvigor/releases).

   - Method 2: Build from the source code.
   > Note: KubeEye files will be generated in `/usr/local/bin/` on your machine.

   ```shell
   git clone https://github.com/imaginekube/kvigor.git
   cd kvigor
   make installkv
   ```

2. (Optional) Install [Node-problem-Detector](https://github.com/kubernetes/node-problem-detector).

   > Note: If you need detailed reports, run the following command, and then NPD will be installed on your cluster.

   ```shell
   kvigor install npd
   ```
3. Run KVigor to inspect clusters.

> Note: The results of KVigor are sorted by resource kind.

```shell
kvigor audit
KIND          NAMESPACE        NAME                                                           REASON                                        LEVEL    MESSAGE
Node                           docker-desktop                                                 kubelet has no sufficient memory available   warning    KubeletHasNoSufficientMemory
Node                           docker-desktop                                                 kubelet has no sufficient PID available      warning    KubeletHasNoSufficientPID
Node                           docker-desktop                                                 kubelet has disk pressure                    warning    KubeletHasDiskPressure
Deployment    default          testkvigor                                                                                                                   NoCPULimits
Deployment    default          testkvigor                                                                                                                   NoReadinessProbe
Deployment    default          testkvigor                                                                                                                   NotRunAsNonRoot
Deployment    kube-system      coredns                                                                                                               NoCPULimits
Deployment    kube-system      coredns                                                                                                               ImagePullPolicyNotAlways
Deployment    kube-system      coredns                                                                                                               NotRunAsNonRoot
Deployment    kviogr-system    kvigor-controller-manager                                                                                             ImagePullPolicyNotAlways
Deployment    kvigor-system    kvigor-controller-manager                                                                                             NotRunAsNonRoot
DaemonSet     kube-system      kube-proxy                                                                                                            NoCPULimits
DaemonSet     k          ube-system      kube-proxy                                                                                                            NotRunAsNonRoot
Event         kube-system      coredns-558bd4d5db-c26j8.16d5fa3ddf56675f                      Unhealthy                                    warning   Readiness probe failed: Get "http://10.1.0.87:8181/ready": dial tcp 10.1.0.87:8181: connect: connection refused
Event         kube-system      coredns-558bd4d5db-c26j8.16d5fa3fbdc834c9                      Unhealthy                                    warning   Readiness probe failed: HTTP probe failed with statuscode: 503
Event         kube-system      vpnkit-controller.16d5ac2b2b4fa1eb                             BackOff                                      warning   Back-off restarting failed container
Event         kube-system      vpnkit-controller.16d5fa44d0502641                             BackOff                                      warning   Back-off restarting failed container
Event         kubeeye-system   kubeeye-controller-manager-7f79c4ccc8-f2njw.16d5fa3f5fc3229c   Failed                                       warning   Failed to pull image "controller:latest": rpc error: code = Unknown desc = Error response from daemon: pull access denied for controller, repository does not exist or may require 'docker login': denied: requested access to the resource is denied
Event         kvigor-system    kvigor-controller-manager-7f79c4ccc8-f2njw.16d5fa3f61b28527   Failed                                         warning   Error: ImagePullBackOff
Role          kvigor-system   kvigor-leader-election-role                                                                                            CanDeleteResources
ClusterRole                    kvigor-manager-role                                                                                                   CanDeleteResources
ClusterRole                    kvigor-manager-role                                                                                                   CanModifyWorkloads
ClusterRole                    vpnkit-controller                                                                                                     CanImpersonateUser
ClusterRole                    vpnkit-controller                                                                                           CanDeleteResources
```

## How KVigor can help you

- It inspects cluster resources according to Kubernetes best practices to ensure that clusters run stably.
- It detects the control plane problems of the cluster, including kube-apiserver, kube-controller-manager, and etcd.
- It detects node problems, including memory, CPU, disk pressure, and unexpected kernel error logs.

## Checklist

|Yes/No |Check Item |Description |Severity |
|---|---|---|---|
| :white_check_mark: | PrivilegeEscalationAllowed     | Privilege escalation is allowed. | danger |
| :white_check_mark: | CanImpersonateUser             | The Role/ClusterRole can impersonate users. | warning |
| :white_check_mark: | CanModifyResources             | The Role/ClusterRole can delete Kubernetes resources. | warning |
| :white_check_mark: | CanModifyWorkloads             | The Role/ClusterRole can modify Kubernetes resources. | warning |
| :white_check_mark: | NoCPULimits                    | No CPU limits are set. | danger |
| :white_check_mark: | NoCPURequests                  | No CPU resources are reserved. | danger |
| :white_check_mark: | HighRiskCapabilities           | High-risk features, such as ALL, SYS_ADMIN, and NET_ADMIN, are enabled. | danger |
| :white_check_mark: | HostIPCAllowed                 | HostIPC is set to `true`. | danger |
| :white_check_mark: | HostNetworkAllowed             | HostNetwork is set to `true`. | danger |
| :white_check_mark: | HostPIDAllowed                 | HostPID is set to `true`. | danger |
| :white_check_mark: | HostPortAllowed                | HostPort is set to `true`. | danger |
| :white_check_mark: | ImagePullPolicyNotAlways       | The image pull policy is not set to `always`. | warning |
| :white_check_mark: | ImageTagIsLatest               | The image tag is `latest`. | warning |
| :white_check_mark: | ImageTagMiss                   | The image tag is missing. | danger |
| :white_check_mark: | InsecureCapabilities           | Insecure options are missing, such as KILL, SYS_CHROOT, and CHOWN. | danger |
| :white_check_mark: | NoLivenessProbe                | Liveless probe is not set. | warning |
| :white_check_mark: | NoMemoryLimits                 | No memory limits are set. | danger |
| :white_check_mark: | NoMemoryRequests               | No memory resources are reserved. | danger |
| :white_check_mark: | NoPriorityClassName            | Resource scheduling priority is not set. | ignore |
| :white_check_mark: | PrivilegedAllowed              | Pods are running in the privileged mode. | danger |
| :white_check_mark: | NoReadinessProbe               | Readiness probe is not set. | warning |
| :white_check_mark: | NotReadOnlyRootFilesystem      | readOnlyRootFilesystem is not set to `true`. | warning |
| :white_check_mark: | NotRunAsNonRoot                | runAsNonRoot is not set to `true`. | warning |
| :white_check_mark: | CertificateExpiredPeriod       | The certificate expiry date of the API Server is less than 30 days. | danger |
| :white_check_mark: | EventAudit                     | Events need to be audited. | warning |
| :white_check_mark: | NodeStatus                     | Node status needs to be checked. | warning |
| :white_check_mark: | DockerStatus                   | Docker status needs to be checked. | warning |         
| :white_check_mark: | KubeletStatus                  | kubelet status needs to be checked. | warning |

## Add your own inspection rules
### Add custom OPA rules

1. Create a directory for storing OPA rules.

   ```shell
   mkdir opa
   ```
2. Add custom OPA rule files.

   > Note:
   - OPA rule for checking workloads: The package name must be *kvigor_workloads_rego*.
   - OPA rule for checking RBAC settings: The package name must be *kvigor_RBAC_rego*.
   - OPA rule for checking node settings: The package name must be *kvigor_nodes_rego*.

3. To check whether the image registry address complies with rules, save the following rules to *imageRegistryRule.rego* 

  ```rego
  package kvigor_workloads_rego

  deny[msg] {
      resource := input
      type := resource.Object.kind
      resourcename := resource.Object.metadata.name
      resourcenamespace := resource.Object.metadata.namespace
      workloadsType := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
      workloadsType[type]

      not workloadsImageRegistryRule(resource)

      msg := {
          "Name": sprintf("%v", [resourcename]),
          "Namespace": sprintf("%v", [resourcenamespace]),
          "Type": sprintf("%v", [type]),
          "Message": "ImageRegistryNotmyregistry"
      }
  }

  workloadsImageRegistryRule(resource) {
      regex.match("^myregistry.public.kubesphere/basic/.+", resource.Object.spec.template.spec.containers[_].image)
  }
  ```

4. Run KVigor with custom rules.

  > Note: KVigor will read all files ending with *.rego* in the directory.

  ```shell
  root:# kvigor audit -p ./opa
  NAMESPACE     NAME              KIND          MESSAGE
  default       nginx1            Deployment    [ImageRegistryNotmyregistry NotReadOnlyRootFilesystem NotRunAsNonRoot]
  default       nginx11           Deployment    [ImageRegistryNotmyregistry PrivilegeEscalationAllowed HighRiskCapabilities HostIPCAllowed HostPortAllowed ImagePullPolicyNotAlways ImageTagIsLatest InsecureCapabilities NoPriorityClassName PrivilegedAllowed NotReadOnlyRootFilesystem NotRunAsNonRoot]
  default       nginx111          Deployment    [ImageRegistryNotmyregistry NoCPULimits NoCPURequests ImageTagMiss NoLivenessProbe NoMemoryLimits NoMemoryRequests NoPriorityClassName NotReadOnlyRootFilesystem NoReadinessProbe NotRunAsNonRoot]
  ```

### Add custom NPD rules

1. Run the following command to change the ConfigMap:

   ```shell
   kubectl edit ConfigMap node-problem-detector-config -n kube-system 
   ```
2. Run the following command to restart NPD:

   ```shell
   kubectl rollout restart DaemonSet node-problem-detector -n kube-system
   ```

## KubeEye Operator
### What is KVigor Operator

KVigor Operator is an inspection platform for Kubernetes. It manages KVigor to regularly inspect clusters and generate inspection results.

### How KVigor Operator can help you

- It records inspection results by using CR and provide a web page for you to intuitively view and compare cluster inspection results.
- It provides more plugins.
- It provides more detailed modification suggestions.

### Deploy KubeEye Operator

```shell
kubectl apply -f https://raw.githubusercontent.com/imaginekube/kvigor/main/deploy/kvigor.yaml
kubectl apply -f https://raw.githubusercontent.com/imaginekube/kvigor/main/deploy/kvigor_insights.yaml
```
### Obtain the inspection results

```shell
kubectl get clusterinsight -o yaml
```

```shell
apiVersion: v1
items:
- apiVersion: kvigor.imaginekube.io/v1alpha1
  kind: ClusterInsight
  metadata:
    name: clusterinsight-sample
    namespace: default
  spec:
    auditPeriod: 24h
  status:
    auditResults:
      auditResults:
      - resourcesType: Node
        resultInfos:
        - namespace: ""
          resourceInfos:
          - items:
            - level: warning
              message: KubeletHasNoSufficientMemory
              reason: kubelet has no sufficient memory available
            - level: warning
              message: KubeletHasNoSufficientPID
              reason: kubelet has no sufficient PID available
            - level: warning
              message: KubeletHasDiskPressure
              reason: kubelet has disk pressure
            name: kvigorNode
```


## Related Documents

* [RoadMap](docs/roadmap.md)
* [FAQ](docs/FAQ.md)
