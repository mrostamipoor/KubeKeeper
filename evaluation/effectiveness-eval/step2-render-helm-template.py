import os
import subprocess
import logging
import sys
import yaml

def setup_logging(log_file, unrendered_log_file):
    """Set up logging for errors and unrendered Helm charts"""
    logging.basicConfig(filename=log_file, level=logging.ERROR,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    handler = logging.FileHandler(unrendered_log_file)
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    path_logger = logging.getLogger('unrendered')
    path_logger.setLevel(logging.WARNING)
    path_logger.addHandler(handler)
    return path_logger


def find_configurations(directory):
    """Find all Helm charts and Kustomize configurations, renaming non-standard files to standard names."""
    config_dirs = []

    for root, dirs, files in os.walk(directory):
        # Detect Chart.yaml/yml and values.yaml/yml files with different names
        chart_files = [f for f in files if 'chart' in f.lower() and f.endswith(('.yaml', '.yml'))]
        values_files = [f for f in files if 'values' in f.lower() and f.endswith(('.yaml', '.yml'))]
        has_templates = any("template" in d.lower() for d in dirs)

        def file_exists(root, base_name):
            """Check if either .yaml or .yml version of a file exists in the given directory."""
            return any(os.path.exists(os.path.join(root, f"{base_name}.{ext}")) for ext in ["yaml", "yml"])

        # Handle Chart.yaml/yml renaming safely
        if chart_files:
            chart_yaml_path = os.path.join(root, "Chart.yaml")
            chart_yml_path = os.path.join(root, "Chart.yml")

            #if file_exists(root, "Chart"):
            #    print(f"✅ Chart.yaml or Chart.yml already exists in {root}, skipping renaming.")
            if len(chart_files) == 1:
                # Only one candidate file exists, rename it safely to `.yaml`
                old_path = os.path.join(root, chart_files[0])
                os.rename(old_path, chart_yaml_path)
                #print(f"🔄 Renamed {old_path} to {chart_yaml_path}")
            #else:
            #    # Multiple candidates found, log a warning
            #    print(f"⚠️ Multiple chart files found in {root}: {chart_files}, skipping rename.")

        # Handle values.yaml/yml renaming safely
        if values_files:
            values_yaml_path = os.path.join(root, "values.yaml")
            values_yml_path = os.path.join(root, "values.yml")

            #if file_exists(root, "values"):
            #    print(f"✅ values.yaml or values.yml already exists in {root}, skipping renaming.")
            if len(values_files) == 1:
                # Only one candidate file exists, rename it safely to `.yaml`
                old_path = os.path.join(root, values_files[0])
                os.rename(old_path, values_yaml_path)
                #print(f"🔄 Renamed {old_path} to {values_yaml_path}")


        # Standard detection logic after renaming
        if file_exists(root, "Chart") and file_exists(root, "values") and has_templates:
            config_dirs.append(root)

        if "kustomization.yaml" in files or "kustomization.yml" in files or ".argocd" in dirs:
            config_dirs.append(root)

        logging.info(f"Skipped directory: {root}")

    return config_dirs

def parse_disabled_features(values_yaml_path):
    """Parse values.yaml to find keys set to false and generate --set flags"""
    try:
        with open(values_yaml_path, 'r') as file:
            values = yaml.safe_load(file)

        disabled_flags = []

        def traverse_dict(d, prefix=""):
            """Recursively find disabled features"""
            for key, value in d.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    traverse_dict(value, full_key)
                elif value is False:
                    disabled_flags.append(f"{full_key}=true")

        return disabled_flags

    except Exception as e:
        logging.warning(f"Failed to parse {values_yaml_path}: {e}")
        return []

def detect_missing_settings(values_yaml_path):
    """Detect required Helm settings to avoid rendering errors"""
    required_settings = {}

    try:
        with open(values_yaml_path, 'r') as file:
            values = yaml.safe_load(file)

        # Check for required settings that should not be empty
        if "config" in values:
            if "kvstore" in values["config"]:
                if "store" not in values["config"]["kvstore"] or not values["config"]["kvstore"]["store"]:
                    required_settings["config.kvstore.store"] = "memberlist"  # Default to memberlist

            if "ruler" in values["config"]:
                if "enable_sharding" not in values["config"]["ruler"]:
                    required_settings["config.ruler.enable_sharding"] = "true"

    except Exception as e:
        logging.warning(f"Failed to analyze {values_yaml_path}: {e}")

    return required_settings

def run_helm_template(config_dir, flags):
    """Run Helm template command and return error output if any"""
    set_flags_str = " ".join([f"--set {flag}" for flag in flags]) if flags else ""
    command = f"helm template {config_dir} {set_flags_str} --debug --dry-run"

    #print(f"Running Helm dry-run for: {config_dir} with flags: {set_flags_str}")
    
    result = subprocess.run(command, shell=True, text=True, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)


    if "Error:" in result.stderr:
        #print(f"Error detected in {config_dir}: {result.stderr.strip()}")
        return result.stderr.strip()  # Return the error message
    return None  

def run_kustomize_build(config_dir):
    """Run Kustomize build and return the output YAML or error message."""
    command = f"kustomize build {config_dir}"
    
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True, check=True)
        return result.stdout  # Return the rendered YAML output
    except subprocess.CalledProcessError as e:
        logging.warning(f"Kustomize build failed for {config_dir}: {e.stderr.strip()}")
        return None  # Return None if Kustomize build fails


def remove_problematic_flags(config_dir, set_flags):
    """Remove flags one by one if they cause errors until the command succeeds"""
    if not set_flags:
        return []

    flags_to_test = set_flags.copy()
    removed_flags = []

    while flags_to_test:
        error_message = run_helm_template(config_dir, flags_to_test)

        if error_message:
            logging.warning(f"Helm error detected: {error_message}")

            # Try to identify which flag is causing the issue
            for flag in flags_to_test:
                test_flags = flags_to_test.copy()
                test_flags.remove(flag)

                if not run_helm_template(config_dir, test_flags):
                    removed_flags.append(flag)
                    flags_to_test.remove(flag)
                    #print(f"Removed problematic flag: {flag}")
                    break  # Restart checking process
        else:
            break  # No errors found, use the current flag set

    return flags_to_test  # Return only the working flags
def render_helm_configuration(config_dir, unrendered_log_file):
    """Render Helm configurations with necessary flag adjustments."""
    values_yaml_path = os.path.join(config_dir, 'values.yaml')

    # Step 1: **Build Dependencies**
    #print(f"🔄 Running `helm dependency build` for {config_dir}...")
    build_command = f"helm dependency build {config_dir}"
    try:
        subprocess.run(build_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #print(f"✅ Dependencies built successfully for {config_dir}\n")
    except subprocess.CalledProcessError as e:
        logging.warning(f"Helm dependency build failed for {config_dir}: {e.stderr.strip()}")
        #print(f"⚠️ Helm dependency build failed for {config_dir}: {e.stderr.strip()}")

    # Step 2: Detect missing settings and parse disabled features
    missing_settings = detect_missing_settings(values_yaml_path)
    set_flags = parse_disabled_features(values_yaml_path)

    # Merge missing settings with disabled features
    for key, value in missing_settings.items():
        set_flags.append(f"{key}={value}")

    # Step 3: Remove problematic flags dynamically
    working_flags = remove_problematic_flags(config_dir, set_flags)

    # Step 4: Run Helm template
    set_flags_str = " ".join([f"--set {flag}" for flag in working_flags]) if working_flags else ""
    output_file = os.path.join(config_dir, 'rendered.yaml')
    command = f"helm template {config_dir} {set_flags_str} > {output_file}"

    try:
        subprocess.run(command, shell=True, check=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        #print(f"✅ Successfully rendered Helm chart: {config_dir}\n")
    except subprocess.CalledProcessError as e:
        logging.warning(f"Rendering failed for {config_dir}: {e}")
        handle_render_error(config_dir, e, unrendered_log_file)


def render_configurations(config_dirs, unrendered_log_file):
    """Render Helm configurations after fixing missing settings and removing problematic flags"""
    for config_dir in config_dirs:
        #print(f"\nProcessing Helm chart: {config_dir}")
        if os.path.exists(os.path.join(config_dir, 'kustomization.yaml')):
            # Process Kustomize
            #print(f"Processing Kustomize configuration: {config_dir}")
            rendered_yaml = run_kustomize_build(config_dir)

            if rendered_yaml:
                output_file = os.path.join(config_dir, 'rendered.yaml')
                with open(output_file, 'w') as f:
                    f.write(rendered_yaml)
                #print(f"✅ Successfully rendered Kustomize configuration: {config_dir}\n")
            else:
                #print(f"❌ Failed to render Kustomize configuration: {config_dir}")
                handle_render_error(config_dir, "Kustomize build failed", unrendered_log_file)
                #print(f"❌ Failed back")
        else:
            render_helm_configuration(config_dir, unrendered_log_file)

def handle_render_error(config_dir, error, unrendered_log_file):
    """Log failed renderings for debugging"""
    logging.warning(f"Error rendering configuration in {config_dir}: {error}")
    with open(unrendered_log_file, 'a') as file:
        file.write(f"{config_dir}\n")

def main(directory, project_type):
    """Main function to find Helm charts and render them dynamically"""
    log_file = os.path.join('./logs/', project_type + '_render_errors.log')
    unrendered_log_file = os.path.join('./logs/', project_type + '_unrendered_log.log')
    setup_logging(log_file, unrendered_log_file)

    config_dirs = find_configurations(directory)
    if config_dirs:
        render_configurations(config_dirs, unrendered_log_file)

if __name__ == "__main__":
    project_type = sys.argv[1]
    current_directory = os.getcwd()
    project_dir = os.path.join(current_directory, project_type + '-third-party-apps')

    for item in os.listdir(project_dir):
        item_path = os.path.join(project_dir, item)
        if os.path.isdir(item_path):
            main(item_path, project_type)
