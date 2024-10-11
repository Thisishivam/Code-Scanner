import re
import os

def scan_file(filename):
    vulnerabilities = []
    reported_vulnerabilities = set()  

    # Define regex patterns for common vulnerabilities and secrets
    secret_patterns = [
        r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*([\'"]?)([A-Za-z0-9/+=]{32,})\2',  
        r'(?i)(password|token)\s*=\s*([\'"]?)(.+?)\2',  
        r'(?i)(key|token)\s*[:=]\s*([\'"]?)([A-Za-z0-9/+=]{32,})\2',  
        r'\b[A-Za-z0-9]{32,}\b' 
    ]

    # Check for potential vulnerabilities in the code
    vulnerability_patterns = {
        r'eval\(': "Avoid using eval() as it can execute arbitrary code. Use safer alternatives.",
        r'exec\(': "Avoid using exec() for similar reasons. Refactor to avoid dynamic code execution.",
        r'os\.system\(': "Avoid os.system() for executing shell commands. Use subprocess.run() instead.",
        r'subprocess\.Popen\(': "Ensure input validation when using subprocess.Popen().",
        r'input\(': "Avoid using input() directly. Use safer input methods or validation.",
        r'os\.environ': "Be cautious with environment variables. Ensure they are not exposed.",
        r'open\(.+\s*,\s*["\']w["\']': "Avoid opening files in write mode without careful validation.",
        r'shutil\.copy': "Be cautious with file copying. Validate source and destination paths.",
        r'system\(': "Avoid using system calls that can be exploited. Use safer alternatives.",
        r'\b(input|print)\s*\(.*\)': "Be cautious with output/input functions that may expose sensitive information.",
        r'HTTP.*request\(': "Ensure proper validation and sanitization of user inputs in HTTP requests.",
        r'\b(open|read|write|delete|exec|system)\s*\(': "Check for unsafe operations that could be exploited.",
        r'(?i)(base64\.decode|base64\.b64decode)\s*\(': "Ensure inputs are properly validated before decoding base64.",
        r'\b(while|for|if)\s*.*:\s*#\s*.*(debug|debugger|testing)\b': "Remove debug statements before production."
    }

    # Check for suspicious variable names
    suspicious_variable_names = [
        r'\b(secret|token|key|passwd|password|credential|database|db_username|db_password|username|github_token|github-token|uname)\b'
    ]

    # Define vulnerable import patterns and their usage patterns
    import_patterns = {
        r'import\s+pickle': r'eval\(|exec\(|load\(|dumps\(|loads\(',
        r'import\s+os': r'os\.system\(|os\.environ',
        r'import\s+subprocess': r'subprocess\.Popen\(|subprocess\.call',
        r'import\s+shutil': r'shutil\.copy\(|shutil\.move',
        r'import\s+socket': r'socket\.connect\(|socket\.bind',
        r'import\s+threading': r'threading\.Thread\(',
    }

    if not os.path.isfile(filename):
        print(f"The file {filename} does not exist.")
        return
    
    with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
        contents = file.readlines()

        # Check for secrets and variables
        for line in contents:
            for pattern in secret_patterns:
                match = re.search(pattern, line)
                if match:
                    vulnerabilities.append(f"Found potential secret: '{match.group()}'")

            for pattern in suspicious_variable_names:
                match = re.search(pattern, line)
                if match:
                    # Extract the entire assignment statement
                    assignment_match = re.search(r'(\w+)\s*=\s*(.*)', line)
                    if assignment_match:
                        var_name = assignment_match.group(1)
                        var_value = assignment_match.group(2).strip()
                        vulnerabilities.append(f"Found suspicious variable '{var_name}' with value '{var_value}'")

        # Check for vulnerabilities and unsafe imports
        for line in contents:
            for pattern, recommendation in vulnerability_patterns.items():
                if re.search(pattern, line):
                    vulnerability_id = (pattern, recommendation)
                    if vulnerability_id not in reported_vulnerabilities:
                        vulnerabilities.append(f"Found potentially dangerous usage: {line.strip()}")
                        vulnerabilities.append(f"Recommendation: {recommendation}\n")
                        reported_vulnerabilities.add(vulnerability_id)

            # Check for vulnerable imports
            for import_pattern, usage_pattern in import_patterns.items():
                if re.search(import_pattern, line):
                    # Look for unsafe usages of the imported module
                    for subsequent_line in contents[contents.index(line):]:
                        if re.search(usage_pattern, subsequent_line):
                            import_id = (import_pattern, "Be cautious with import usage.")
                            if import_id not in reported_vulnerabilities:
                                vulnerabilities.append(f"Found unsafe usage of import: {import_pattern.strip()} in {subsequent_line.strip()}")
                                vulnerabilities.append(f"Recommendation: Be cautious with import usage.")
                                reported_vulnerabilities.add(import_id)
                            break

    if vulnerabilities:
        print("Potential issues found:")
        for issue in vulnerabilities:
            print(f"- {issue}")
    else:
        print("No vulnerabilities or secrets found.")

if __name__ == "__main__":
    filename = input("Enter the filename to scan: ")
    scan_file(filename)
