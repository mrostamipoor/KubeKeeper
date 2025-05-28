#!/bin/bash

kubectl delete deployment nginx-deployment --namespace=production
kubectl delete deployment redis-deployment --namespace=production
kubectl delete deployment node-deployment --namespace=production
kubectl delete deployment python-deployment --namespace=production
kubectl delete deployment postgres-deployment --namespace=production
kubectl delete deployment tensorflow-deployment --namespace=production
kubectl delete deployment elasticsearch-deployment --namespace=production
kubectl delete deployment jenkins-deployment --namespace=production
