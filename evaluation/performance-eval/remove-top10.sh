#!/bin/bash

kubectl delete -f nginx-deployment.yaml
kubectl delete -f alpine-deployment.yaml
kubectl delete -f busybox-deployment.yaml
kubectl delete -f redis-deployment.yaml
kubectl delete -f httpd-deployment.yaml
kubectl delete -f memcached-deployment.yaml
kubectl delete -f mariadb-deployment.yaml
kubectl delete -f rabbitmq-deployment.yaml
kubectl delete -f traefik-deployment.yaml
kubectl delete -f python-deployment.yaml