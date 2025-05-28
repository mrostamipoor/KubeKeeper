#!/bin/bash

# Create YAML for nginx
cat <<EOF > nginx-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: production
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
        - name: nginx
          image: nginx:1.14.2
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

# Create YAML for redis
cat <<EOF > redis-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-deployment
  namespace: production
  labels:
    app: redis
spec:
  replicas: 3
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
        - name: redis
          image: redis
          volumeMounts:
            - name: secret-volume
              mountPath: /etc/secret
              readOnly: true
      volumes:
        - name: secret-volume
          secret:
            secretName: new-secret
EOF

# Create YAML for node
cat <<EOF > node-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: node-deployment
  namespace: production
  labels:
    app: node
spec:
  replicas: 3
  selector:
    matchLabels:
      app: node
  template:
    metadata:
      labels:
        app: node
    spec:
      containers:
        - name: node
          image: node
          volumeMounts:
            - name: secret-volume
              mountPath: /etc/secret
              readOnly: true
      volumes:
        - name: secret-volume
          secret:
            secretName: new-secret
EOF

# Create YAML for python
cat <<EOF > python-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: python-deployment
  namespace: production
  labels:
    app: python
spec:
  replicas: 3
  selector:
    matchLabels:
      app: python
  template:
    metadata:
      labels:
        app: python
    spec:
      containers:
        - name: python
          image: python
          volumeMounts:
            - name: secret-volume
              mountPath: /etc/secret
              readOnly: true
      volumes:
        - name: secret-volume
          secret:
            secretName: new-secret
EOF

# Create YAML for postgres
cat <<EOF > postgres-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres-deployment
  namespace: production
  labels:
    app: postgres
spec:
  replicas: 3
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: postgres
          volumeMounts:
            - name: secret-volume
              mountPath: /etc/secret
              readOnly: true
      volumes:
        - name: secret-volume
          secret:
            secretName: new-secret
EOF

# Create YAML for tensorflow
cat <<EOF > tensorflow-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tensorflow-deployment
  namespace: production
  labels:
    app: tensorflow
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tensorflow
  template:
    metadata:
      labels:
        app: tensorflow
    spec:
      containers:
        - name: tensorflow
          image: tensorflow/tensorflow
          volumeMounts:
            - name: secret-volume
              mountPath: /etc/secret
              readOnly: true
      volumes:
        - name: secret-volume
          secret:
            secretName: new-secret
EOF

# Create YAML for elasticsearch
cat <<EOF > elasticsearch-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: elasticsearch-deployment
  namespace: production
  labels:
    app: elasticsearch
spec:
  replicas: 3
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      containers:
        - name: elasticsearch
          image: elasticsearch
          volumeMounts:
            - name: secret-volume
              mountPath: /etc/secret
              readOnly: true
      volumes:
        - name: secret-volume
          secret:
            secretName: new-secret
EOF

# Create YAML for jenkins
cat <<EOF > jenkins-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jenkins-deployment
  namespace: production
  labels:
    app: jenkins
spec:
  replicas: 3
  selector:
    matchLabels:
      app: jenkins
  template:
    metadata:
      labels:
        app: jenkins
    spec:
      containers:
        - name: jenkins
          image: jenkins/jenkins
          volumeMounts:
            - name: secret-volume
              mountPath: /etc/secret
              readOnly: true
      volumes:
        - name: secret-volume
          secret:
            secretName: new-secret
EOF
