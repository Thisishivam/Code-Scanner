# Code-Scanner
This Python script scans files for potential security vulnerabilities and hardcoded secrets. It uses regular expressions to identify common patterns that may indicate unsafe practices or the presence of sensitive information.

## Features

- Detects hardcoded secrets such as API keys, tokens, and passwords.
- Identifies potentially dangerous code patterns, including the use of `eval()`, `exec()`, and shell commands.
- Alerts on suspicious variable names that may expose sensitive information.
- Checks for unsafe imports and their usages.

## Installation

  Make sure you have Python installed on your machine. Clone this repository and navigate to the project directory:
   ```shell
   git clone https://github.com/Thisishivam/Code-Scanner
   cd Code-Scanner
   ```

## Usage

  Run the script with the target filename as input:
  
  ```shell
  python scan.py
  ```
  You will be prompted to enter the filename to scan:
  
  ```shell
  Enter the filename to scan: your_script.py
  ```

## Example Output

  ![Screenshot](https://github.com/Thisishivam/Code-Scanner/blob/main/Scan1.png)

  ![Screenshot](https://github.com/Thisishivam/Code-Scanner/blob/main/Scan2.png)
