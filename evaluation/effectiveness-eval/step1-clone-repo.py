import os
import subprocess
import sys

def main(input_file, unparsed_log_file, project_type):
    # Ensure the project directory exists
    project_dir = './'+project_type+'-third-party-apps'
    os.makedirs(project_dir, exist_ok=True)
    
    # Ensure the log directory exists
    log_dir = os.path.dirname(unparsed_log_file)
    os.makedirs(log_dir, exist_ok=True)
    
    # Read the repository URLs from the input file
    with open(input_file, 'r') as file:
        repos = file.readlines()
    
    # Process each repository URL
    for repo in repos:
        repo = repo.strip()
        if not repo:
            continue
        
        try:
            # Clone the repository
            subprocess.run(['git', 'clone', repo, os.path.join(project_dir, os.path.basename(repo).replace('.git', ''))],
                           check=True)
            print(f"Successfully cloned {repo}")
        except subprocess.CalledProcessError as e:
            # Log the error to the unparsed log file
            with open(unparsed_log_file, 'a') as log_file:
                log_file.write(f"Failed to clone {repo}: {e}\n")
            print(f"Failed to clone {repo}. Logged the error.")

if __name__ == "__main__":
    # Define the input file and the log file for unparsed errors
    project_type=sys.argv[1]
    input_file = '../dataset/'+project_type+'_repo_links.txt'
    error_log_file = './logs/'+project_type+'-uncloned-repos.log'
    main(input_file, error_log_file,project_type)
