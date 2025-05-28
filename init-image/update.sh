#!/bin/sh


docker image rmi decrypt-image:v1.0.0
docker build -t  decrypt-image:v1.0.0 .


kind load docker-image decrypt-image:v1.0.0 --name kind

