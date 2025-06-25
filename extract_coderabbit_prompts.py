import re
import json
import subprocess

pr_number = "80"

# First try to get comments in markdown format
result = subprocess.run([
    'gh', 'api', f'repos/dashpay/rust-dashcore/pulls/{pr_number}/comments',
    '--paginate', '--jq', '.[] | select(.user.login == "coderabbitai[bot]") | "## File: \\(.path) (Line: \\(.line // "file-level"))\\n\\n\\(.body)\\n\\n---\\n"'
], capture_output=True, text=True)

if result.returncode == 0:
    content = result.stdout
    
    # Find all AI agent prompts
    pattern = r'🤖 Prompt for AI Agents</summary>\n\n```\n(.*?)\n```\n\n</details>'
    prompts = re.findall(pattern, content, re.DOTALL)
    
    # Also extract file and line information
    file_pattern = r'## File: (.*?) \(Line: (.*?)\)\n'
    files_and_lines = re.findall(file_pattern, content)
    
    # Save each prompt to a separate file with metadata
    task_count = 0
    for i, prompt in enumerate(prompts, 1):
        prompt = prompt.strip()
        
        # Try to match with file info
        file_info = ""
        if i-1 < len(files_and_lines):
            file_path, line = files_and_lines[i-1]
            file_info = f"# File: {file_path}\n# Line: {line}\n\n"
        
        with open(f'coderabbit_pr_{pr_number}_tasks/pr_{pr_number}_task_{i}.md', 'w') as f:
            f.write(file_info + prompt + '\n')
        
        task_count += 1
    
    print(f"Extracted {task_count} tasks from PR #{pr_number}")
else:
    print(f"Error fetching comments: {result.stderr}")