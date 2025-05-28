#!/bin/bash

kubectl apply -f nginx-deployment.yaml
kubectl apply -f alpine-deployment.yaml
kubectl apply -f busybox-deployment.yaml
kubectl apply -f redis-deployment.yaml
kubectl apply -f httpd-deployment.yaml
kubectl apply -f memcached-deployment.yaml
kubectl apply -f mariadb-deployment.yaml
kubectl apply -f rabbitmq-deployment.yaml
kubectl apply -f traefik-deployment.yaml
kubectl apply -f python-deployment.yaml