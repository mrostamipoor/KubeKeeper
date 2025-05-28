import csv
import json
import os
import yaml
import sys
from itertools import product
import json
import pandas as pd
def extract_combinations(permission):
    # Split the permission string into verbs, resources, api_groups, and optionally resource_names
    parts = permission.split('::')
    if len(parts) < 3:
        raise ValueError(f"Invalid permission format: {permission}")

    verbs = parts[0].split(',')
    resources = parts[1].split(',')
    api_groups = parts[2].split(',')

    # Check if resource names are present (optional part)
    resources_names = parts[3].split(',') if len(parts) > 3 else ['whole']

    # Create combinations of verb, resource, api_group, and resources_names
    combinations = list(product(verbs, resources, api_groups, resources_names))
    
    # Format combinations into 'verb::resource::apigroup::resource_names'
    formatted_combinations = [f"{verb}::{resource}::{api_group}::{resource_name}" for verb, resource, api_group, resource_name in combinations]

    return formatted_combinations


def is_example_path(file_path):
    """Identify if the file path belongs to examples."""
    example_keywords = ['example', 'demo', 'test']  
    return any(keyword in file_path.lower() for keyword in example_keywords)

categories = {
    'Direct Access via Secret Permissions': {
        'verbs': {'get', 'watch', 'list','*'},
        'resources': {'secrets','serviceaccounts/token','*'}
    },
    'Indirect Access via Secret Manipulation': {
        'verbs': { 'patch', 'update'},
        'resources': {'secrets','serviceaccounts/token'}
    },
    'Indirect Access via Resource Scheduling Control': {
        'verbs': {'create','patch', 'update', '*'},
        'resources': {
            'pods', 
            'daemonsets', 'deployments', 'statefulsets', 'replicasets',
            'cronjobs', 'jobs'
        }
    },
    'Indirect Access via Node Manipulation': {
        'verbs': { 'patch', 'update', '*'},
        'resources': {
              'nodes',
        }
    }

}


def categorize_permission(verbs, resources):
    for category, criteria in categories.items():
        if verbs & criteria['verbs'] and resources & criteria['resources']:
            return category
    print(verbs,resources)
    return 'Unkown'

def extract_define_namespace(yaml_content, file_path, namespace_usage, unparsed_files):
    try:
        documents = yaml.safe_load_all(yaml_content)
        for doc in documents:
            if isinstance(doc, dict) and doc.get('kind', '') == 'Namespace':
                metadata = doc.get('metadata', {})
                namespace_name = metadata.get('name', '')
                namespace_usage.add(namespace_name)
    except yaml.YAMLError as e: 
        unparsed_files.append(file_path)
    return namespace_usage

def extract_service_account_usage(yaml_content, file_path, service_account_usage, unparsed_files):
    try:
        documents = yaml.safe_load_all(yaml_content)
        for doc in documents:
            if isinstance(doc, dict) and doc.get('kind', '') in ['Pod', 'Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet']:
                metadata = doc.get('metadata', {})
                spec = doc.get('spec', {})

                if doc['kind'] == 'Pod':
                    service_account_name = spec.get('serviceAccountName', 'default')
                else:
                    template_spec = spec.get('template', {}).get('spec', {})
                    service_account_name = template_spec.get('serviceAccountName', 'default')
                namespace = 'default'
                resource_name= ''
                if isinstance(metadata, dict):
                    namespace = metadata.get('namespace', 'default')
                    resource_name = metadata.get('name', '')
                kind = doc.get('kind', '')

                if service_account_name != 'default':
                    usage_details = {'namespace': namespace, 'name': resource_name, 'kind': kind}
                    if service_account_name in service_account_usage:
                        service_account_usage[service_account_name].append(usage_details)
                    else:
                        service_account_usage[service_account_name] = [usage_details]
    except yaml.YAMLError as e:
        unparsed_files.append(file_path)
    #print(f"path file {file_path}: {service_account_usage}")

    return service_account_usage

def extract_cluster_roles(yaml_content, file_path, cluster_role_permissions, unparsed_files):
    """Extracts ClusterRoles, tracking their permissions, labels, and aggregation rules.
       At the end, applies aggregation rules by merging permissions based on matching labels."""

    roleClassification = 'Example configs' if is_example_path(file_path) else 'Main configs'
    aggregated_roles = {} 

    try:
        documents = yaml.safe_load_all(yaml_content)
        for doc in documents:
            if isinstance(doc, dict) and doc.get('kind', '') == 'ClusterRole':
                cluster_role_name = doc.get('metadata', {}).get('name', '')
                metadata = doc.get('metadata', {})
                rules = doc.get('rules', [])
                labels = metadata.get('labels', {})

                # Track Aggregation Rules
                aggregation_rule = doc.get('aggregationRule', {})
                if aggregation_rule:
                    cluster_role_permissions[cluster_role_name] = []  # Initially empty
                    selectors = aggregation_rule.get('clusterRoleSelectors', [])
                    for selector in selectors:
                        match_labels = selector.get('matchLabels', {})
                        for label, value in match_labels.items():
                            if label not in aggregated_roles:
                                aggregated_roles[label] = set()
                            aggregated_roles[label].add(cluster_role_name)

                # Extract Permissions (If Not an Aggregated Role)
                permissions = []
                if isinstance(rules, list):
                    for rule in rules:
                        permissions.append({
                            'verbs': set(rule.get('verbs', [])),
                            'resources': set(rule.get('resources', [])),
                            'apiGroups': set(rule.get('apiGroups', [])),
                            'resourceNames': set(rule.get('resourceNames', [])),
                            'roleClassification': roleClassification,
                            'labels': labels,  
                            'aggregationRule': aggregation_rule  
                        })
                    
                    cluster_role_permissions[cluster_role_name] = permissions
                else:
                    # Handle invalid rules format
                    unparsed_files.append(f"{file_path}: Invalid 'rules' format")

    except yaml.YAMLError as e:
        unparsed_files.append(file_path)

    # **Apply Aggregation Rules**
    for label, parent_roles in aggregated_roles.items():
        for role, permissions in cluster_role_permissions.items():
            if permissions:
                role_labels = permissions[0].get('labels', {}) or {}  # Ensure role_labels is always a dictionary
            else:
                role_labels = {} 

            if role_labels.get(label) == "true":
                # This role matches an aggregation rule, add its permissions to parent roles
                for parent_role in parent_roles:
                    if parent_role in cluster_role_permissions:
                        cluster_role_permissions[parent_role].extend(permissions)

    return cluster_role_permissions 




def extract_roles(yaml_content, file_path, app_name, role_permissions, unparsed_files, used_namespaces):
    roleClassification = 'Example configs' if is_example_path(file_path) else 'Main configs'

    try:
        documents = yaml.safe_load_all(yaml_content)
        for doc in documents:
            if isinstance(doc, dict) and doc.get('kind', '') == 'Role':
                role_name = doc.get('metadata', {}).get('name', '')
                namespace = doc.get('metadata', {}).get('namespace', 'default') or 'default'
                
                # Skip namespaces that match certain conditions
                if namespace in used_namespaces or app_name in namespace:
                    continue
                elif 'kube-system' == namespace or 'default' == namespace:
                    permissions = []
                    for rule in doc.get('rules', []):
                        verbs = set(rule.get('verbs', []))
                        resources = set(rule.get('resources', []))
                        api_groups = set(rule.get('apiGroups', []))
                        # Extract resourceNames if available
                        resource_names = set(rule.get('resourceNames', []))  
                        
                        permissions.append({
                            'namespace': namespace,
                            'verbs': verbs,
                            'resources': resources,
                            'apiGroups': api_groups,
                            'resourceNames': resource_names,  
                            'roleClassification': roleClassification
                        })
                    role_permissions[role_name] = permissions
    except yaml.YAMLError as e:
        unparsed_files.append(file_path)

    return role_permissions

def extract_cluster_role_bindings(yaml_content, file_path, cluster_role_bindings, unparsed_files):
    bindingClassification = 'Example configs' if is_example_path(file_path) else 'Main configs'

    try:
        documents = yaml.safe_load_all(yaml_content)
        for doc in documents:
            if isinstance(doc, dict) and doc.get('kind', '') == 'ClusterRoleBinding':
                role_ref = doc.get('roleRef', {}).get('name', '')
                subjects = doc.get('subjects', [])
                for sub in subjects:
                    if isinstance(sub, dict):
                        name = sub.get('name', '')
                        kind = sub.get('kind', '')
                        namespace = sub.get('namespace', 'default')
                        if kind == 'ServiceAccount':
                            if role_ref in cluster_role_bindings:
                                cluster_role_bindings[role_ref].append({'name': name, 'namespace': namespace, 'kind': kind, 'bindingClassification': bindingClassification})
                            else:
                                cluster_role_bindings[role_ref] = [{'name': name, 'namespace': namespace, 'kind': kind, 'bindingClassification': bindingClassification}]
    except yaml.YAMLError as e:
        unparsed_files.append(yaml_content)


    return cluster_role_bindings

def extract_role_bindings(yaml_content, file_path, app_name, role_bindings, unparsed_files, used_namespaces):
    bindingClassification = 'Example configs' if is_example_path(file_path) else 'Main configs'
    
    try:
        documents = yaml.safe_load_all(yaml_content)
        for doc in documents:
            if isinstance(doc, dict) and doc.get('kind', '') == 'RoleBinding':
                namespace = doc.get('metadata', {}).get('namespace', 'default') or 'default'
                if namespace in used_namespaces or app_name in namespace:
                    continue
                elif 'kube-system' == namespace or 'default' == namespace:
                    role_ref = doc.get('roleRef', {}).get('name', '')
                    subjects = doc.get('subjects', [])
                    
                    for sub in subjects:
                        if isinstance(sub, dict) and sub.get('kind', '') == 'ServiceAccount':
                            name = sub.get('name', '')
                            sa_namespace = sub.get('namespace', namespace)  
                            
                            if role_ref in role_bindings:
                                role_bindings[role_ref].append({
                                    'name': name, 
                                    'namespace': sa_namespace, 
                                    'bindingNamespace': namespace,
                                    'kind': 'ServiceAccount',                             
                                    'bindingClassification': bindingClassification
                                })
                            else:
                                role_bindings[role_ref] = [{
                                    'name': name, 
                                    'namespace': sa_namespace, 
                                    'bindingNamespace': namespace,
                                    'kind': 'ServiceAccount', 
                                    'bindingClassification': bindingClassification
                                }]
    except yaml.YAMLError as e:
        unparsed_files.append(file_path)

    return role_bindings

def merge_cluster_role_data(role_permissions, role_bindings):
    merged_data = {}
    
    # Loop through all roles and their bindings
    for role, bindings in role_bindings.items():
        for binding in bindings:
            sa_name = binding['name']
            namespace = binding['namespace']
            bindingClassification = binding['bindingClassification']

            # Initialize service account data if not already present
            if sa_name not in merged_data:
                merged_data[sa_name] = {
                    'clusterRoles': set(),
                    'clusterBindings': set(),
                    'permissions': set(),
                    'resourceNames': set(),  # Added to store resourceNames
                    'namespace': 'default',
                    'bindingClassification': set(),
                    'roleClassification': set()
                }
                
            # Add role and binding details to the merged data
            merged_data[sa_name]['clusterRoles'].add(role)
            merged_data[sa_name]['namespace'] = namespace
            merged_data[sa_name]['clusterBindings'].add(f"{binding['kind']}/{binding['name']}")
            merged_data[sa_name]['bindingClassification'].add(bindingClassification)

            # Process the role permissions
            if role in role_permissions:
                for perm in role_permissions[role]:
                    # Extract verbs, resources, API groups, and resourceNames
                    verbs = ','.join(perm['verbs'])
                    resources = ','.join(perm['resources'])
                    api_groups = perm['apiGroups']
                    roleClassification = perm['roleClassification']
                    resource_names = perm.get('resourceNames', [])  # List of resourceNames

                    # Determine if permission applies to specific resources or whole
                    if resource_names:
                        # Specific resources
                        resource_name_string = ','.join(resource_names)
                        permission_string = f"{verbs}::{resources}::{','.join(api_groups or ['core'])}::specific"
                        # Store resource names
                        merged_data[sa_name]['resourceNames'].add(resource_name_string)
                    else:
                        # Whole resources (no specific resourceNames)
                        permission_string = f"{verbs}::{resources}::{','.join(api_groups or ['core'])}::whole"
                    
                    # Add role classification and permissions to the merged data
                    merged_data[sa_name]['roleClassification'].add(roleClassification)
                    merged_data[sa_name]['permissions'].add(permission_string)
    return merged_data



def merge_role_data(role_permissions, role_bindings):
    merged_data = {}
    for role, bindings in role_bindings.items():
        for binding in bindings:
            sa_name = binding['name']
            namespace = binding['namespace']
            bindingClassification = binding['bindingClassification']
            
            # Initialize service account data if not already present
            if sa_name not in merged_data:
                merged_data[sa_name] = {
                    'roles': set(),
                    'bindings': set(),
                    'rolePermissions': set(),
                    'resourceNames': set(),  
                    'roleNamespace': 'default',
                    'bindingClassification': set(),
                    'roleClassification': set()
                }
                
            # Add role and binding details to the merged data
            merged_data[sa_name]['roles'].add(role)
            merged_data[sa_name]['roleNamespace'] = namespace
            merged_data[sa_name]['bindings'].add(f"{binding['kind']}/{binding['name']}")
            merged_data[sa_name]['bindingClassification'].add(bindingClassification)

            # Process the role permissions
            if role in role_permissions:
                for perm in role_permissions[role]:
                    # Extract verbs, resources, API groups, and resourceNames
                    verbs = ','.join(perm['verbs'])
                    resources = ','.join(perm['resources'])
                    api_groups = perm['apiGroups']
                    roleClassification = perm['roleClassification']
                    resource_names = ','.join(perm.get('resourceNames', []))  

                    # Add role classification and permissions to the merged data
                    merged_data[sa_name]['roleClassification'].add(roleClassification)
                    for api_group in api_groups:
                        group_name = api_group if api_group else 'core'
                        permission_string = f"{verbs}::{resources}::{group_name}"
                        merged_data[sa_name]['rolePermissions'].add(permission_string)

                    # Add resource names to the merged data if present
                    if resource_names:
                        merged_data[sa_name]['resourceNames'].add(resource_names)  

    return merged_data

def correlate_data(service_account_usage, merged_cluster_data, merged_role_data):
    correlated_data = {}

    # Collect all unique service accounts from both datasets
    all_service_accounts = set(merged_cluster_data.keys()).union(merged_role_data.keys())

    for sa_name in all_service_accounts:
        sa_info_cluster = merged_cluster_data.get(sa_name, {})
        sa_info_role = merged_role_data.get(sa_name, {})

        # Extract information from cluster data
        cluster_namespace = sa_info_cluster.get('namespace', 'default') or 'default'
        cluster_permissions = set(sa_info_cluster.get('permissions', []))  
        cluster_roles = set(sa_info_cluster.get('clusterRoles', []))        
        cluster_bindings = set(sa_info_cluster.get('clusterBindings', []))  
        cluster_binding_classification = set(sa_info_cluster.get('bindingClassification', set()))
        cluster_role_classification = set(sa_info_cluster.get('roleClassification', set()))
        cluster_resource_names = set(sa_info_cluster.get('resourceNames', []))  

        # Extract information from role data
        role_namespace = sa_info_role.get('roleNamespace', 'default') or 'default'
        role_permissions = set(sa_info_role.get('rolePermissions', []))     
        roles = set(sa_info_role.get('roles', []))                          
        role_bindings = set(sa_info_role.get('bindings', []))               
        role_binding_classification = set(sa_info_role.get('bindingClassification', set()))
        role_classification = set(sa_info_role.get('roleClassification', set()))
        role_resource_names = set(sa_info_role.get('resourceNames', []))    

        namespace = cluster_namespace + ":" + role_namespace

        # Handle ServiceAccount usage information
        if sa_name in service_account_usage:
            for usage in service_account_usage[sa_name]:
                resource_name = usage.get('name', 'unknown')
                resource_kind = usage.get('kind', 'unknown')

                if sa_name not in correlated_data:
                    correlated_data[sa_name] = {}
                if namespace not in correlated_data[sa_name]:
                    correlated_data[sa_name][namespace] = {}
                if resource_name not in correlated_data[sa_name][namespace]:
                    correlated_data[sa_name][namespace][resource_name] = {
                        'kind': resource_kind,
                        'clusterPermissions': list(cluster_permissions),  
                        'rolePermissions': list(role_permissions),        
                        'clusterRoles': list(cluster_roles),              
                        'roles': list(roles),                           
                        'clusterBindings': list(cluster_bindings),        
                        'roleBindings': list(role_bindings),              
                        'clusterBindingClassification': cluster_binding_classification,
                        'clusterClassification': cluster_role_classification,
                        'roleBindingClassification': role_binding_classification,
                        'roleClassification': role_classification,
                        'clusterResourceNames': list(cluster_resource_names),  
                        'roleResourceNames': list(role_resource_names)         
                    }
                else:
                    # Use update() for sets and convert back to list for storing
                    correlated_data[sa_name][namespace][resource_name]['clusterPermissions'] = list(
                        set(correlated_data[sa_name][namespace][resource_name]['clusterPermissions']).union(cluster_permissions)
                    )
                    correlated_data[sa_name][namespace][resource_name]['rolePermissions'] = list(
                        set(correlated_data[sa_name][namespace][resource_name]['rolePermissions']).union(role_permissions)
                    )
                    correlated_data[sa_name][namespace][resource_name]['clusterRoles'] = list(
                        set(correlated_data[sa_name][namespace][resource_name]['clusterRoles']).union(cluster_roles)
                    )
                    correlated_data[sa_name][namespace][resource_name]['roles'] = list(
                        set(correlated_data[sa_name][namespace][resource_name]['roles']).union(roles)
                    )
                    correlated_data[sa_name][namespace][resource_name]['clusterBindings'] = list(
                        set(correlated_data[sa_name][namespace][resource_name]['clusterBindings']).union(cluster_bindings)
                    )
                    correlated_data[sa_name][namespace][resource_name]['roleBindings'] = list(
                        set(correlated_data[sa_name][namespace][resource_name]['roleBindings']).union(role_bindings)
                    )
                    correlated_data[sa_name][namespace][resource_name]['clusterBindingClassification'].update(cluster_binding_classification)
                    correlated_data[sa_name][namespace][resource_name]['roleBindingClassification'].update(role_binding_classification)
                    correlated_data[sa_name][namespace][resource_name]['clusterClassification'].update(cluster_role_classification)
                    correlated_data[sa_name][namespace][resource_name]['roleClassification'].update(role_classification)
                    # Update resourceNames for both cluster and role
                    correlated_data[sa_name][namespace][resource_name]['clusterResourceNames'] = list(
                        set(correlated_data[sa_name][namespace][resource_name].get('clusterResourceNames', [])).union(cluster_resource_names)
                    )
                    correlated_data[sa_name][namespace][resource_name]['roleResourceNames'] = list(
                        set(correlated_data[sa_name][namespace][resource_name].get('roleResourceNames', [])).union(role_resource_names)
                    )
        else:
            #  Check if the ServiceAccount has ANY roles, bindings, or permissions
            has_roles = bool(cluster_roles or roles)
            has_bindings = bool(cluster_bindings or role_bindings)
            has_permissions = bool(cluster_permissions or role_permissions)

            if has_roles or has_bindings or has_permissions:
                # If the ServiceAccount has any permissions or roles, do NOT mark it as "unbind"
                resource_name = 'active'
                resource_kind = 'default'
            else:
                # If the ServiceAccount has NO permissions, roles, or bindings, then mark it as "unbind"
                resource_name = 'unbind'
                resource_kind = 'default'

            if sa_name not in correlated_data:
                correlated_data[sa_name] = {}
            if namespace not in correlated_data[sa_name]:
                correlated_data[sa_name][namespace] = {}
            if resource_name not in correlated_data[sa_name][namespace]:
                correlated_data[sa_name][namespace][resource_name] = {
                    'kind': resource_kind,
                    'clusterPermissions': list(cluster_permissions),
                    'rolePermissions': list(role_permissions),
                    'clusterRoles': list(cluster_roles),
                    'roles': list(roles),
                    'clusterBindings': list(cluster_bindings),
                    'roleBindings': list(role_bindings),
                    'clusterBindingClassification': cluster_binding_classification,
                    'clusterClassification': cluster_role_classification,
                    'roleBindingClassification': role_binding_classification,
                    'roleClassification': role_classification,
                    'clusterResourceNames': list(cluster_resource_names),  
                    'roleResourceNames': list(role_resource_names)         
                }
            else:
                correlated_data[sa_name][namespace][resource_name]['clusterPermissions'] = list(
                    set(correlated_data[sa_name][namespace][resource_name]['clusterPermissions']).union(cluster_permissions)
                )
                correlated_data[sa_name][namespace][resource_name]['rolePermissions'] = list(
                    set(correlated_data[sa_name][namespace][resource_name]['rolePermissions']).union(role_permissions)
                )
                correlated_data[sa_name][namespace][resource_name]['clusterRoles'] = list(
                    set(correlated_data[sa_name][namespace][resource_name]['clusterRoles']).union(cluster_roles)
                )
                correlated_data[sa_name][namespace][resource_name]['roles'] = list(
                    set(correlated_data[sa_name][namespace][resource_name]['roles']).union(roles)
                )
                correlated_data[sa_name][namespace][resource_name]['clusterBindings'] = list(
                    set(correlated_data[sa_name][namespace][resource_name]['clusterBindings']).union(cluster_bindings)
                )
                correlated_data[sa_name][namespace][resource_name]['roleBindings'] = list(
                    set(correlated_data[sa_name][namespace][resource_name]['roleBindings']).union(role_bindings)
                )
                correlated_data[sa_name][namespace][resource_name]['clusterBindingClassification'].update(cluster_binding_classification)
                correlated_data[sa_name][namespace][resource_name]['roleBindingClassification'].update(role_binding_classification)
                correlated_data[sa_name][namespace][resource_name]['clusterClassification'].update(cluster_role_classification)
                correlated_data[sa_name][namespace][resource_name]['roleClassification'].update(role_classification)
                # Update resourceNames for both cluster and role
                correlated_data[sa_name][namespace][resource_name]['clusterResourceNames'] = list(
                    set(correlated_data[sa_name][namespace][resource_name].get('clusterResourceNames', [])).union(cluster_resource_names)
                )
                correlated_data[sa_name][namespace][resource_name]['roleResourceNames'] = list(
                    set(correlated_data[sa_name][namespace][resource_name].get('roleResourceNames', [])).union(role_resource_names)
                )

    return correlated_data


def parse_permission(permission):
    """Parses a permission string into a dictionary with keys: verbs, Resources, and API groups."""
    parts = permission.split("::")
    return {
        "verbs": parts[0],
        "Resources": parts[1],
        "API groups": parts[2] if len(parts) > 2 else ""
    }
def analyze_permissions(permissions, mode, role_permissions, app_overprivilege_counts):

    combinations = extract_combinations(permissions)
    for perm in combinations:
        is_over_privileged_perm = is_over_privileged(perm)
        if is_over_privileged_perm:
            role_permissions.add(perm)
            parts=perm.split("::")
            if len(parts) < 4:
                print(f"Invalid permission format: {parts}")
                continue            
            resource_names_part = parts[3]
            if resource_names_part != "whole":
                continue
            verbs = set(parts[0].split(','))
            resources = set(parts[1].split(','))
            category = categorize_permission(verbs, resources)
            #if '_cluster' in mode:
            overprivilege_counts[category] += 1
            if category not in app_overprivilege_counts:
                app_overprivilege_counts[category] = 0
            app_overprivilege_counts[category] += 1

            # Ensure the directory exists before writing the file
            output_category_dir = "./output/category/"
            os.makedirs(output_category_dir, exist_ok=True)                

            with open("./output/category/"+category+mode+'.txt', 'a') as category_file:
                category_file.write(f"{perm}\n")


      

def write_to_text_file(app_name, correlated_data, output_dir, critical_permissions):
    # Dictionary to store count of overprivileged permissions per category
    app_overprivilege_counts = {category: 0 for category in categories.keys()} 
    app_overprivilege_counts['Unknown'] = 0
    
    # Define the output file path
    output_file_path = os.path.join(output_dir, f"{app_name}.txt")
    
    # Open the file for writing
    with open(output_file_path, 'w') as output_file:
        for sa_name, namespaces in correlated_data.items():
            for namespace, resources in namespaces.items():
                output_file.write(f"[Service Account]: {sa_name}\n")
                for resource_name, details in resources.items():
                    if 'unbind' in resource_name:
                        continue
                    resource_kind = details['kind']
                    bindingClassification = details['clusterBindingClassification']
                    clusterClassification = details['clusterClassification']
                    roleClassification = details['roleClassification']
                    roleBindingClassification = details['roleBindingClassification']
                    roleNamespace = namespace.split(':')[1]

                    output_file.write(f"  [Resource] (ResourceName/ResourceType): {resource_name}/{resource_kind}\n\n")
                    output_file.write(f"  [Permissions]:\n")

                    # Cluster permissions
                    clusterPermissions = sorted(details['clusterPermissions'])
                    cluster_over_permissions = set()

                    for perm in clusterPermissions:
                        if 'unbind' not in resource_name:
                            analyze_permissions(perm, '_clusterRoles', cluster_over_permissions, app_overprivilege_counts)

                    # Write cluster permissions to file
                    cluster_permissions_json = json.dumps([parse_permission(perm) for perm in clusterPermissions], indent=4)
                    output_file.write(f"    [clusterPermissions]: {cluster_permissions_json}\n")

                    # Write over-privileged permissions if any
                    if cluster_over_permissions:
                        critical_permissions.update(cluster_over_permissions)
                        cluster_over_permissions_json = json.dumps([parse_permission(perm) for perm in cluster_over_permissions], indent=4)
                        output_file.write(f"    [cluster role over-privileged permissions]: {cluster_over_permissions_json}\n\n")
                    else:
                        output_file.write(f"    [cluster role over-privileged permissions]: [] \n\n")

                    # Role permissions
                    rolePermissions = sorted(details['rolePermissions'])
                    role_over_permissions = set()

                    for perm in rolePermissions:
                        if 'unbind' not in resource_name:
                            analyze_permissions(perm, '_roles', role_over_permissions, app_overprivilege_counts)

                    # Write role permissions to file
                    role_permissions_json = json.dumps([parse_permission(perm) for perm in rolePermissions], indent=4)
                    output_file.write(f"    [rolePermissions] ({roleNamespace}): {role_permissions_json}\n")

                    # Write role over-privileged permissions if any
                    if role_over_permissions:
                        critical_permissions.update(role_over_permissions)
                        role_over_permissions_json = json.dumps([parse_permission(perm) for perm in role_over_permissions], indent=4)
                        output_file.write(f"    [role over-privileged permissions]: {role_over_permissions_json}\n\n")
                    else:
                        output_file.write("    [role over-privileged permissions]: [] \n\n")

                    # Print cluster roles and role bindings
                    clusterRoles = sorted(details['clusterRoles'])
                    output_file.write(f"  [Role Details]:\n")
                    output_file.write(f"    [clusterRoles]: [{'; '.join(clusterRoles)}] [{'; '.join(clusterClassification)}]\n")
                    
                    clusterBindings = sorted(details['clusterBindings'])
                    output_file.write(f"    [clusterRoleBindings]: [{'; '.join(clusterBindings)}] [{'; '.join(bindingClassification)}]\n\n")
                    
                    # Print roles and role bindings
                    roles = sorted(details['roles'])
                    output_file.write(f"    [roles]: [{'; '.join(roles)}] [{'; '.join(roleClassification)}]\n")
                    
                    bindings = sorted(details['roleBindings'])
                    output_file.write(f"    [roleBindings]: [{'; '.join(bindings)}] [{'; '.join(roleBindingClassification)}]\n")

                    # Additional data for resourceNames
                    if 'clusterResourceNames' in details and details['clusterResourceNames']:
                        output_file.write(f"    [clusterResourceNames]: {', '.join(details['clusterResourceNames'])}\n")
                    if 'roleResourceNames' in details and details['roleResourceNames']:
                        output_file.write(f"    [roleResourceNames]: {', '.join(details['roleResourceNames'])}\n")

                    output_file.write("-------------------------------------------\n\n")
    
    return app_overprivilege_counts



def is_over_privileged(permissions):

    important_api_groups = {'', '*', 'admissionregistration.k8s.io','core', 'apps', 'batch', 'autoscaling', 'rbac.authorization.k8s.io', 'networking.k8s.io', 'policy', 'storage.k8s.io'}

    critical_verbs_resources = {
        "get": ["secrets", "*","serviceaccounts/token"],
        "watch": ["secrets", "*","serviceaccounts/token"],
        "list": ["secrets", "*","serviceaccounts/token"],
        "patch": [
            "secrets", "nodes", 
            "pods", "daemonsets", "deployments", "statefulsets", "replicasets",
            "cronjobs", "jobs", "serviceaccounts/token"
        ],
        "update": [
            "secrets", "nodes",
            "pods", "daemonsets", "deployments", "statefulsets", "replicasets",
            "cronjobs", "jobs", "serviceaccounts/token"
        ],
        "create": [
            "pods", "daemonsets", "deployments", "statefulsets", "replicasets",
            "cronjobs", "jobs"
        ],
        "*": [
            "secrets", "nodes", 
            "pods", "daemonsets", "deployments", "statefulsets", "replicasets",
            "cronjobs", "jobs", "serviceaccounts/token"
        ]
    }

    def is_critical_permission(verbs, resources, api_groups):
        for verb in verbs:
            if verb in critical_verbs_resources:
                # If the verb is '*', consider all critical verbs
                allowed_resources = set()
                allowed_resources = set(critical_verbs_resources[verb])                
                if any(res in allowed_resources for res in resources) and\
                    any(api_group in important_api_groups for api_group in api_groups):
                    return True
        return False
    
    #for perm in permissions:
    parts = permissions.split('::')
    if len(parts) < 3:
        print(f"Invalid permission format: {parts}")
        return False            

    verbs = set(parts[0].split(','))
    resources = set(parts[1].split(','))
    api_groups = set(parts[2].split(';'))
    if is_critical_permission(verbs, resources, api_groups):
            return True
            
    return False

def check_supported_apps(app_overprivilege_counts):
    access_to_secret_privileges = [
        'Direct Access via Secret Permissions',
        'Indirect Access via Secret Manipulation',
        'Indirect Access via Resource Scheduling Control',
        'Indirect Access via Node Manipulation'

    ]
    categories = [0, 0, 0, 0]
    for privilege in access_to_secret_privileges:
            if privilege != 'Unkown':
                count = app_overprivilege_counts.get(privilege, 0)
                index = access_to_secret_privileges.index(privilege) + 1

                # Safely update the appropriate category based on the index
                if 1 <= index <= 4:  
                    categories[index - 1] += count

    category_1, category_2, category_3, category_4 = categories
    return category_1, category_2, category_3, category_4


def main(csv_input_path, output_dir, unparsed_log_file, over_privileged_csv):
    csv.field_size_limit(sys.maxsize)
    with open(csv_input_path, newline='') as csvfile, open(unparsed_log_file, 'w') as log_file, open(over_privileged_csv, 'w', newline='') as op_csv_file:
        reader = csv.DictReader(csvfile)
        op_writer = csv.writer(op_csv_file)
        op_writer.writerow(['Application Name', 'Over-Privileged', 'Critical Permissions',
                            'Direct Access via Secret Permissions Counts', 'Indirect Access via Secret Manipulation Counts',
                            'Indirect Access via Resource Scheduling Control Counts', 'Indirect Access via Node Manipulation Counts'])

        for row in reader:
            repo_dir = row['Directory Path']
            clusterRole_paths_str = row['ClusterRole Files']
            clusterRole_binding_paths_str = row['ClusterRoleBinding Files']
            role_paths_str = row['Role Files']
            role_binding_paths_str = row['RoleBinding Files']
            sa_usage_files_str = row['ServiceAccount Usage Files']
            defined_namespaces_str = row['Defined Namespaces']
            service_account_usage = {}
            cluster_role_permissions = {}
            cluster_role_bindings = {}
            role_permissions = {}
            role_bindings = {}
            unparsed_files = []
            used_namespaces = set()
            app_name = os.path.basename(os.path.normpath(repo_dir))
            defined_namespaces= []
            sa_usage_files = json.loads(sa_usage_files_str.replace("'", '"'))
            for file in sa_usage_files:
                with open(file, 'r') as f:
                    content_data = f.read()
                    service_account_usage = extract_service_account_usage(
                        content_data, file, service_account_usage, unparsed_files
                        )

            used_namespaces_files = json.loads(defined_namespaces_str.replace("'", '"'))
            for file in used_namespaces_files:
                with open(file, 'r') as f:
                    content_data = f.read()
                    defined_namespaces = extract_define_namespace(
                        content_data, file, used_namespaces, unparsed_files
                        )
            #print(f"defined_namespaces: {defined_namespaces}")
            role_file_paths = json.loads(role_paths_str.replace("'", '"'))
            for role_file_path in role_file_paths:
                with open(role_file_path, 'r') as f:
                    yaml_content = f.read()
                    role_permissions = extract_roles(
                        yaml_content, role_file_path, app_name, role_permissions, unparsed_files, defined_namespaces
                        )
            #print(f"role_permissions: {role_permissions}")

            role_binding_paths = json.loads(role_binding_paths_str.replace("'", '"'))
            for role_binding_file_path in role_binding_paths:
                with open(role_binding_file_path, 'r') as f:
                    yaml_content = f.read()
                    role_bindings = extract_role_bindings(
                        yaml_content, role_binding_file_path, app_name, role_bindings, unparsed_files, defined_namespaces
                        )
            #print(f"role_permissions bindings: {role_bindings}")    

            clusterRole_file_paths = json.loads(clusterRole_paths_str.replace("'", '"'))
            for clusterRole_file_path in clusterRole_file_paths:
                with open(clusterRole_file_path, 'r') as f:
                    yaml_content = f.read()
                    cluster_role_permissions = extract_cluster_roles(
                        yaml_content, clusterRole_file_path, cluster_role_permissions, unparsed_files
                        )
            
            clusterRole_binding_paths = json.loads(clusterRole_binding_paths_str.replace("'", '"'))
            for clusterRole_binding_path in clusterRole_binding_paths:
                with open(clusterRole_binding_path, 'r') as f:
                    yaml_content = f.read()
                    cluster_role_bindings = extract_cluster_role_bindings(
                        yaml_content, clusterRole_binding_path, cluster_role_bindings, unparsed_files
                        )


            merged_cluster_data = merge_cluster_role_data(cluster_role_permissions, cluster_role_bindings)
            #print(f"merged_cluster_data: {merged_cluster_data}")
            merged_role_data = merge_role_data(role_permissions, role_bindings)
            #print(f"merged_role_data: {merged_role_data}")

            correlated_data = correlate_data(service_account_usage, merged_cluster_data, merged_role_data)

            critical_permissions = set()
            app_overprivilege_counts= write_to_text_file(app_name, correlated_data, output_dir, critical_permissions)
            category_1, category_2, category_3, category_4 = check_supported_apps(app_overprivilege_counts)
            if unparsed_files:
                log_file.write(f"{repo_dir}: {', '.join(unparsed_files)}\n")
            protected = 'N/A'

            if int(category_1) != 0 or int(category_2) != 0 or int(category_3) != 0 or int(category_4) != 0:
                    protected = True

            op_writer.writerow([
                app_name,
                protected,
                #'; '.join(sorted(unique_permissions)),
                '; '.join(sorted(critical_permissions)),
                category_1, category_2, category_3, category_4
            ])

if __name__ == "__main__":
    project_type_main = sys.argv[1]

    overprivilege_counts = {category: 0 for category in categories.keys()}
    overprivilege_counts['Unknown'] = 0
    overprivilege_counts['Wildcard Access to All Resources']=0
    apps= []
    apps.append(project_type_main)

    for project_type in apps:
        csv_input_path = './output/' + project_type + '_output.csv'
        output_dir = './output/' + project_type + '_text_files'
        os.makedirs(output_dir, exist_ok=True)
        unparsed_log_file = './logs/' + project_type + '_unparsed_files.log'
        over_privileged_csv = './output/' + project_type + '_over_privileged.csv'
        main(csv_input_path, output_dir, unparsed_log_file, over_privileged_csv)
    print(f"Over-privileged counts: {overprivilege_counts}")
    # Convert the dictionary to a DataFrame
    # Specified order of categories
    specified_order = [
        'Direct Access via Secret Permissions',
        'Indirect Access via Secret Manipulation',
        'Indirect Access via Resource Scheduling Control',
        'Indirect Access via Node Manipulation'
    ]

    # Convert the dictionary to a DataFrame
    df = pd.DataFrame(list(overprivilege_counts.items()), columns=['Category', 'Count'])

    # Reorder the DataFrame based on the specified order
    df_ordered = df.set_index('Category').loc[specified_order].reset_index()

    # Save the ordered DataFrame to a CSV file
    file_path = project_type_main+"_overprivilege_counts.csv"
    df_ordered.to_csv(file_path, index=False)