#!/bin/bash

#kubectl apply -f ./manifests/blockedserviceaccounts.yaml
kubectl delete secret new-secret -n production
kubectl apply -f ./manifests/deploy_protectedSecret.yaml
kubectl delete deployment nginx-deployment -n production
kubectl create -f manifests/deploy_deployment_withProtectedSecret.yaml