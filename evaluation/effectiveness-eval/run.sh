#!/bin/bash



environments=("graduated" "incubating" "sandbox" google" "amazon" "azure" "alibaba" "publicdataset" "additionalapplication")

for env in "${environments[@]}"; do
    echo "Processing $env environment..."
    python3 step1-clone-repo.py "$env"
    python3 step2-render-helm-template.py "$env"
    python3 step3-extract-ClusterRoles.py "$env"
    python3 step4-extract-excessivePermissions.py "$env"
    
done
echo "All tasks completed."

