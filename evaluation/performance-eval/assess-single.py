import subprocess
import time
import datetime
import pandas as pd
import json
import sys
def get_current_time():
    """Returns the current time as a timestamp."""
    return datetime.datetime.now()

def apply_deployment(deployment_file):
    """Applies the Kubernetes deployment using kubectl."""
    try:
        subprocess.run(["kubectl", "apply", "-f", deployment_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to apply deployment: {deployment_file}")
        print(e)

def get_pod_status(deployment_name, namespace="production"):
    """Retrieves the pod creation and start time for a given deployment."""
    pod_creation_time = None
    pod_start_time = None

    try:
        # Get the pod information in JSON format
        result = subprocess.run(
            ["kubectl", "get", "pods", "-l", f"app={deployment_name}", "-n", namespace, "-o", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        pods = json.loads(result.stdout)

        if pods["items"]:
            # Assume first pod is representative of the deployment
            pod = pods["items"][0]

            # Get pod creation timestamp
            pod_creation_time = pod["metadata"]["creationTimestamp"]

            # Check if pod container has started and get the start time
            container_statuses = pod["status"].get("containerStatuses", [])
            if container_statuses:
                state = container_statuses[0].get("state", {})
                if "running" in state:
                    pod_start_time = state["running"]["startedAt"]

    except subprocess.CalledProcessError as e:
        print(f"Failed to get pod status for deployment: {deployment_name}")
        print(e)

    return pod_creation_time, pod_start_time

def convert_to_timestamp(time_str):
    """Converts Kubernetes time string to a datetime object."""
    if time_str:
        return datetime.datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")
    return None

def calculate_time_difference(initial_time, creation_time, start_time):
    """Calculates the time difference between initial, creation, and start times."""
    print(f"Initial time: {initial_time}, Creation time: {creation_time}, Start time: {start_time}")
    
    creation_diff = (creation_time - initial_time).total_seconds() if creation_time else None
    start_diff = (start_time - creation_time).total_seconds() if start_time and creation_time else None
    
    print(f"Time to create: {creation_diff}, Time to start: {start_diff}")
    return creation_diff, start_diff


def write_to_csv(data, csv_filename="deployment_times.csv"):
    """Writes the timing data (time differences) to a CSV file."""
    df = pd.DataFrame(data, columns=["deployment", "time_to_create", "time_to_start"])
    df.to_csv(csv_filename, index=False)
    print(f"Results written to {csv_filename}")

def main(deployment_name, deployment_file, namespace="production"):
    # Step 1: Record initial time
    initial_time = get_current_time()

    # Step 2: Apply the deployment
    print(f"Deploying {deployment_name}...")
    apply_deployment(deployment_file)

    # Step 3: Wait for pod creation and start times
    pod_creation_time = None
    pod_start_time = None

    # Poll every 5 seconds until pod is created and started
    while not pod_creation_time or not pod_start_time:
        pod_creation_time, pod_start_time = get_pod_status(deployment_name, namespace)
        if not pod_creation_time or not pod_start_time:
            print("Waiting for pod to be created and started...")
        time.sleep(5)

    # Convert pod creation and start times to datetime objects
    pod_creation_time = convert_to_timestamp(pod_creation_time)
    pod_start_time = convert_to_timestamp(pod_start_time)

    # Step 4: Calculate time differences
    time_to_create, time_to_start = calculate_time_difference(initial_time, pod_creation_time, pod_start_time)

    # Step 5: Output the time differences to CSV
    data = [[deployment_name, time_to_create, time_to_start]]
    write_to_csv(data)

if __name__ == "__main__":
    # Deployment name and YAML file path
    #deployment_name = input("Enter the deployment name: ")
    deployment_name = sys.argv[1]
    deployment_file = f"{deployment_name}-deployment.yaml"  # Assume the deployment file is named like "<name>-deployment.yaml"

    # Run the main function
    main(deployment_name, deployment_file)
