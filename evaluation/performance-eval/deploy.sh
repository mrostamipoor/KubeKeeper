#!/bin/bash

kubectl apply -f nginx-deployment.yaml
kubectl apply -f redis-deployment.yaml
kubectl apply -f node-deployment.yaml
kubectl apply -f python-deployment.yaml
kubectl apply -f postgres-deployment.yaml
kubectl apply -f tensorflow-deployment.yaml
kubectl apply -f elasticsearch-deployment.yaml
kubectl apply -f jenkins-deployment.yaml