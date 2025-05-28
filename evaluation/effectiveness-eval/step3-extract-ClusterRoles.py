import os
import csv
import sys
import re
def ensure_directories():
    """Ensure that required directories exist."""
    for directory in ['./output', './logs']:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

def is_helm_template_excluding_data_block(yaml_content: str) -> bool:
    """
    Detect Helm templating outside of the `data:` block.
    This is a more conservative check that avoids false positives
    from embedded templates in ConfigMaps or CRDs.
    """
    # Matches blocks like:
    # data:
    #   some-key: |
    #     stuff with {{ .Values.thing }}
    data_block_pattern = re.compile(r'^data:\n(?:\s{2,}.*\n)+', re.MULTILINE)

    # Remove data blocks entirely
    stripped = data_block_pattern.sub('', yaml_content)

    # Now check for Helm templating outside data blocks
    return bool(re.search(r'{{[^}]+}}|\.\b(Values|Chart|Release)\b', stripped))

def check_yaml_files(directory):
    cluster_role_files = []
    role_files = []
    cluster_role_binding_files = []
    role_binding_files = []
    sa_usage_files = []
    namespace_files = []
    helm_keywords = ['{{-', '{{ if', '{{ else', '{{ include', '{{ template', '.Values', '.Chart', '.Release']
    
    #helm_template_pattern = re.compile(r"{{.*?}}|\.Values|\.Chart|\.Release")
    for root, dirs, files in os.walk(directory):
        # Skip directories that contain "test" in their name
        if any(skip_word in root for skip_word in ['test', 'tests','e2e', 'integration']):
            continue
        
        for file in files:
            
            if file.endswith(('.yaml', '.yml')):
                #print(file)
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        content_data = f.read()
                        #is_helm_template = bool(helm_template_pattern.search(content_data))
                        is_helm_template = is_helm_template_excluding_data_block(content_data)
                        #if "serving-core.yaml" in file:
                        #print(is_helm_template)
                        is_helm_template=bool(is_helm_template)
                        if 'kind: ClusterRole' in content_data and (not is_helm_template or file=='rendered.yaml' ):
                            cluster_role_files.append(file_path)
                        if 'kind: ClusterRoleBinding' in content_data and (not is_helm_template or file=='rendered.yaml' ):
                            cluster_role_binding_files.append(file_path)
                        if 'kind: Role' in content_data and (not is_helm_template or file=='rendered.yaml' ):
                            role_files.append(file_path)
                        if 'kind: RoleBinding' in content_data and (not is_helm_template or file=='rendered.yaml' ):
                            role_binding_files.append(file_path)
                        if 'kind: Namespace' in content_data and (not is_helm_template or file=='rendered.yaml' ):
                            namespace_files.append(file_path)
                        if any(kind in content_data for kind in ['Pod', 'CronJob', 'Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet']) and (not is_helm_template or file=='rendered.yaml' ):
                            sa_usage_files.append(file_path)
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
    #print(cluster_role_files)
    return cluster_role_files, cluster_role_binding_files, role_files, role_binding_files, sa_usage_files, namespace_files

def process_directories(project_type):
    ensure_directories()
    
    output_file = f'./output/{project_type}_output.csv'
    current_directory = os.getcwd()
    project_dir = os.path.join(current_directory, f'{project_type}-third-party-apps')
    
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Directory Path', 'ClusterRole Files', 'ClusterRoleBinding Files', 'Role Files', 'RoleBinding Files', 'ServiceAccount Usage Files', 'Defined Namespaces']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for dir in os.listdir(project_dir):
            
            directory = os.path.join(project_dir, dir)
            if os.path.isdir(directory):
                #print(directory)
                #print("-----------------------------------------------------------------------------------")
                try:
                    cluster_role_files, cluster_role_binding_files, role_files, role_binding_files, sa_usage_files, namespace_files = check_yaml_files(directory)
                    writer.writerow({
                        'Directory Path': directory,
                        'ClusterRole Files': cluster_role_files,
                        'ClusterRoleBinding Files': cluster_role_binding_files,
                        'Role Files': role_files,
                        'RoleBinding Files': role_binding_files,
                        'ServiceAccount Usage Files': sa_usage_files,
                        'Defined Namespaces': namespace_files
                    })
                except Exception as e:
                    print(f"Failed to process directory {directory}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <project_type>")
        sys.exit(1)
    
    project_type = sys.argv[1]
    process_directories(project_type)