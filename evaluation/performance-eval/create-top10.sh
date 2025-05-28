#!/bin/bash

# List of container images
declare -A images
images=(
  ["nginx"]="nginx:1.14.2"
  ["alpine"]="alpine:3.14"
  ["busybox"]="busybox:1.32"
  ["redis"]="redis:6.2"
  ["httpd"]="httpd:2.4"
  ["memcached"]="memcached:1.6"
  ["mariadb"]="mariadb:10.5"
  ["rabbitmq"]="rabbitmq:3.8"
  ["traefik"]="traefik:v2.5"
  ["python"]="python:3.9"
)

# Loop through the images and create a YAML for each
for app in "${!images[@]}"; do
  image=${images[$app]}

  # Create YAML file for each deployment
  cat <<EOF > ${app}-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${app}-deployment
  namespace: production
  labels:
    app: ${app}
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ${app}
  template:
    metadata:
      labels:
        app: ${app}
    spec:
      containers:
        - name: ${app}
          image: ${image}
          ports:
            - containerPort: 80
          volumeMounts:
            - name: secret-volume
              mountPath: /etc/secret
              readOnly: true
      volumes:
        - name: secret-volume
          secret:
            secretName: new-secret
EOF

  echo "Created ${app}-deployment.yaml"

done
