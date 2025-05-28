#!/bin/bash


echo "building images"
docker image rmi kubekeeper:v1.0.0
docker build -t  kubekeeper:v1.0.0 ./webhook-server

docker image rmi init-image:v1.0.0
docker build -t  init-image:v1.0.0 ./init-image/

echo "Creating Cluster"
kind create cluster --config manifests/kubekeeper-cluster.yaml

kubectl delete mutatingwebhookconfiguration deployment-mutation secret-mutation 
kubectl delete service kubekeeper -n kubekeeper
kubectl delete deployment kubekeeper -n kubekeeper
kubectl delete secret kubekeeper-tls -n kubekeeper

echo "loading images"
kind load docker-image kubekeeper:v1.0.0 --name kind
kind load docker-image init-image:v1.0.0 --name kind

echo "Creating certificates"
rm -rf certs
mkdir certs
openssl genrsa -out certs/tls.key 2048
openssl req -new -key certs/tls.key -out certs/tls.csr -subj "/CN=kubekeeper.kubekeeper.svc"
openssl x509 -req -extfile <(printf "subjectAltName=DNS:kubekeeper.kubekeeper.svc") -in certs/tls.csr -signkey certs/tls.key -out certs/tls.crt

echo "Creating Namespace kubekeeper and production"
kubectl create namespace production
kubectl create namespace kubekeeper


echo "Apply blocked service account"
kubectl apply -f manifests/blockedserviceaccounts.yaml

echo "Creating Webhook Server TLS Secret"
kubectl create secret tls kubekeeper-tls \
    --cert "certs/tls.crt" \
    --key "certs/tls.key" -n kubekeeper

echo "Creating Webhook Server Deployment"
kubectl create -f manifests/kubekeeper-webhookserver.yaml -n kubekeeper

echo "Creating K8s Webhooks"
ENCODED_CA=$(cat certs/tls.crt | base64 | tr -d '\n')
sed -e 's@${ENCODED_CA}@'"$ENCODED_CA"'@g' <"manifests/kubekeeper-webhooks.yaml" | kubectl create -f -