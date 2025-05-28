# KubeKeeper: Fine-Grained Protection for Kubernetes Secrets

**KubeKeeper** is a Kubernetes extension that provides fine-grained access control and strong encryption for Kubernetes Secrets, preventing unauthorized access due to excessive permissions or insecure defaults. It integrates with Kubernetes Admission Control and does not require changes to application code.
This project is based on our [research paper](https://mrostamipoor.github.io/files/kubekeeper.pdf), accepted at **IEEE European Symposium on Security and Privacy (Euro S&P) 2025**.  


## Why KubeKeeper?

Kubernetes' built-in secrets management suffers from several critical limitations:

- **Secrets are stored unencrypted by default.**
- **Even with RBAC, workloads/users can access any Secret in their Namespace if misconfigured.**
- **Excessive permissions are common, especially with third-party applications.**

**KubeKeeper** addresses these issues by automatically encrypting Secrets and strictly controlling which Pods can access their decrypted values.

---

## Table of Contents
- [Features](#features)
- [Quick Start](#quick-start)
- [Example Usage](#example-usage)
- [Effectiveness Evaluation](#effectiveness-evaluation)
- [Performance Evaluation](#performance-evaluation)
- [Citation](#citation)

---

## Features

- **Automatic Encryption:** All Secrets are stored and transmitted in encrypted form.
- **Fine-Grained Access Control:** Only authorized Pods can decrypt and use specific Secrets.
- **Seamless Integration:** No changes required to your application code.
- **Static Analysis Tool:** Detects excessive permissions in your Kubernetes YAMLs.
- **Minimal Overhead:** No runtime impact on your workloads.

---

## Quick Start

### 1. Prerequisites

- Linux/macOS machine
- Docker
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- No Kubernetes cluster required (Kind will be set up automatically)

---

### 2. Install Kubernetes and Kind

Run the provided script to install [Kind](https://kind.sigs.k8s.io/) and set up a local Kubernetes cluster:

```bash
./install_k8s.sh

```

---

### 3. Deploy KubeKeeper

To deploy KubeKeeper and its webhook server, simply run:

```bash
./deploy_kubekeeper.sh

```

---

### 4. Deploy a Protected Secret and Consumer Deployment

Deploy a sample Secret (protected by KubeKeeper) and a Deployment that consumes this Secret:

```bash
./deploy_samples.sh
```

---
## Example Usage


To deploy a protected Secret with KubeKeeper, simply add:

- the `protected-secret: "true"` label, and
- the `secret-ownerships` annotation specifying which Pod (or other workload) is authorized to access this Secret.

For any Pod (or Deployment) that should access a protected Secret, add the label:

- `protected-secret-access: "true"`

These minimal changes are all that’s needed—**no changes to your application code are required**. KubeKeeper’s admission controller and webhooks will handle the rest, automatically encrypting the Secret and ensuring only authorized Pods can decrypt and use it.


### Sample Secret Manifest (manifests/deploy_protectedSecret.yaml)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: secret-data
  namespace: production
  annotations:
    secret-ownerships: "example-pod:Pod:production"
  labels:
    protected-secret: "true"
type: Opaque
data:
  sensitivedata: bmV3dGVzdAo=
```
### Sample Deployment Manifest (manifests/deploy_deployment_withProtectedSecret.yaml)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
  namespace: production
  labels:
    protected-secret-access: "true"
spec:
  volumes:
    - name: secret-volume
      secret:
        secretName: secret-data
  containers:
    - name: test-container
      image: nginx:1.14.2
      volumeMounts:
        - name: secret-volume
          mountPath: "/etc/secret-volume"
```

---
## Effectiveness Evaluation

To reproduce the effectiveness evaluation results reported in our [paper](https://mrostamipoor.github.io/files/kubekeeper.pdf), you can use the scripts and datasets provided in the repository.

The evaluation scripts are located in ` evaluation/effectiveness-eval/ `.

- **How to run:**
1. Navigate to the evaluation directory:
   
    ```bash
    cd evaluation/effectiveness-eval/
    ```
3. Run the evaluation script:

   
    ```bash
    ./run.sh
    ```
   
This will execute our static analysis tool on all applications listed in the dataset, which is provided as text files in ` evaluation/dataset/ `.


----

## Performance Evaluation

To check the performance evaluation results, you can navigate to the performance evaluation directory and run the performance assessment Python script:
  
```bash
cd evaluation/performance-eval/
python3 assess.py
```

----
## Citation

If you use KubeKeeper in your research, please cite:

```@inproceedings{rostamipoor2025kubekeeper,
  title={KubeKeeper: Protecting Kubernetes Secrets Against Excessive Permissions},
  author={Maryam Rostamipoor, Aliakbar Sadeghi, Michalis Polychronakis},
  booktitle={Proceedings of IEEE European Symposium on Security and Privacy (Euro S&P)},
  year={2025}
}
```

