import subprocess
import time
import datetime
import pandas as pd
import json
import os

def get_current_time():
    """Returns the current time as a timestamp in ISO 8601 format with second-level precision."""
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

def apply_deployment(deployment_file):
    """Applies the Kubernetes deployment using kubectl."""
    try:
        subprocess.run(["kubectl", "apply", "-f", deployment_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to apply deployment: {deployment_file}")
        print(e)

def delete_deployment(deployment_name, namespace="production"):
    """Deletes the Kubernetes deployment using kubectl."""
    try:
        deployment_name = deployment_name + '-deployment'
        subprocess.run(["kubectl", "delete", "deployment", deployment_name, "-n", namespace], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to delete deployment: {deployment_name}")
        print(e)

def remove_docker_images():
    """Removes all unused Docker images to ensure there's no caching."""
    try:
        subprocess.run(["docker", "system", "prune", "-af"], check=True)
    except subprocess.CalledProcessError as e:
        print("Failed to remove cached images.")
        print(e)

def get_pod_status(deployment_name, namespace="production"):
    """Retrieves the pod creation and start time for a given deployment."""
    pod_creation_time = None
    pod_start_time = None
    pod_phase = None

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

            # Check pod phase (e.g., Pending, Running, Succeeded)
            pod_phase = pod["status"]["phase"]

            # Check if pod container is in "ContainerCreating" or has started running
            container_statuses = pod["status"].get("containerStatuses", [])
            if container_statuses:
                state = container_statuses[0].get("state", {})
                if "waiting" in state:
                    reason = state["waiting"].get("reason", "")
                    if reason == "ContainerCreating":
                        pod_phase = "ContainerCreating"
                elif "running" in state:
                    pod_start_time = state["running"]["startedAt"]
                elif "terminated" in state:  # Handle Completed state
                    pod_start_time = state["terminated"].get("finishedAt")
                    pod_phase = "Succeeded"  # Set phase to Succeeded if terminated

    except subprocess.CalledProcessError as e:
        print(f"Failed to get pod status for deployment: {deployment_name}")
        print(e)

    return pod_creation_time, pod_start_time, pod_phase

def convert_to_timestamp(time_str):
    """Converts Kubernetes time string to a datetime object."""
    if time_str:
        return datetime.datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")
    return None

def calculate_time_difference(initial_time, creation_time, start_time):
    """Calculates the time difference between initial, creation, and start times."""
    creation_diff = (creation_time - initial_time).total_seconds() if creation_time else None
    start_diff = (start_time - creation_time).total_seconds() if start_time and creation_time else None
    return creation_diff, start_diff

def write_to_csv(data, csv_filename="deployment_times.csv"):
    """Writes the timing data (time differences) to a CSV file."""
    df = pd.DataFrame(data, columns=["deployment", "time_to_create", "time_to_start"])
    # Append to the CSV file if it already exists
    if os.path.exists(csv_filename):
        df.to_csv(csv_filename, mode='a', header=False, index=False)
    else:
        df.to_csv(csv_filename, index=False)
    print(f"Results written to {csv_filename}")

def process_deployment(deployment_name, deployment_file, namespace="production", csv_filename="deployment_times.csv"):
    # Step 1: Record initial time
    initial_time_str = get_current_time()
    initial_time = convert_to_timestamp(initial_time_str)

    # Step 2: Apply the deployment
    print(f"Deploying {deployment_name}...")
    apply_deployment(deployment_file)

    # Step 3: Wait for pod creation and start times
    pod_creation_time = None
    pod_start_time = None
    pod_phase = None
    poll_interval = 5  
    max_wait_time = 900  

    total_wait_time = 0
    # Poll every 5 seconds until pod is created and reaches either Running or Completed phase
    while total_wait_time < max_wait_time:
        pod_creation_time, pod_start_time, pod_phase = get_pod_status(deployment_name, namespace)
        
        if pod_phase == "ContainerCreating":
            print(f"Pod {deployment_name} is still in ContainerCreating state...")
        elif pod_phase in ["Running", "Succeeded"]:
            if pod_start_time:
                print(f"Pod {deployment_name} is now in {pod_phase} state and started.")
                break  # Break the loop once we capture the start time
        else:
            print(f"Waiting for pod {deployment_name} to be created and started... Phase: {pod_phase}")
        
        time.sleep(poll_interval)
        total_wait_time += poll_interval

    if not pod_start_time:
        print(f"Warning: Pod {deployment_name} did not start within the expected time frame.")

    # Convert pod creation and start times to datetime objects
    pod_creation_time = convert_to_timestamp(pod_creation_time)
    pod_start_time = convert_to_timestamp(pod_start_time)

    # Step 4: Calculate time differences
    time_to_create, time_to_start = calculate_time_difference(initial_time, pod_creation_time, pod_start_time)

    # Step 5: Output the time differences to CSV
    data = [[deployment_name, time_to_create, time_to_start]]
    write_to_csv(data, csv_filename)

    # Step 6: Remove the deployment
    print(f"Deleting {deployment_name}...")
    delete_deployment(deployment_name, namespace)

    # Step 7: Clear Docker images to remove caching
    print("Clearing cached Docker images...")
    remove_docker_images()

def main():
    # List of deployments and YAML files
    deployments = [
        ("nginx", "./yamls/ginx-deployment.yaml"),
        ("redis", "./yamls/redis-deployment.yaml"),
        ("node", "./yamls/node-deployment.yaml"),
        ("python", "./yamls/python-deployment.yaml"),
        ("postgres", "./yamls/postgres-deployment.yaml"),
        ("elasticsearch", "./yamls/elasticsearch-deployment.yaml"),
        ("jenkins", "./yamls/jenkins-deployment.yaml")
    ]

    # CSV filename
    csv_filename = "deployment_times.csv"

    # Process each deployment
    for deployment_name, deployment_file in deployments:
        process_deployment(deployment_name, deployment_file, csv_filename=csv_filename)

if __name__ == "__main__":
    main()
