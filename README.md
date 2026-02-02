Cerberus Enterprise Edition is a powerful tool designed to protect your repositories from security breaches by detecting and alerting on potential security risks. This tool utilizes a combination of regex patterns and Shannon entropy calculations to identify sensitive information, and integrates with the SARIF standard for seamless security alerts.

Features:
Regex Pattern Matching: Cerberus uses a predefined set of high-confidence regex patterns to match common sensitive information such as AWS keys, Gemini keys, OpenAPI keys, and more.
Shannon Entropy Calculations: In addition to regex matching, Cerberus calculates the Shannon entropy of strings to identify potential secrets that may not match known regex patterns.
SARIF Integration: Cerberus generates a results.sarif file that can be uploaded to GitHub, allowing for easy integration with the Security tab of your repository.
Exclusion Logic: Cerberus allows for customizable exclusion of files and directories using a .cerberusignore file, ensuring that only relevant files are scanned.
Support for Local Folders: Cerberus can be run against local folders, making it easy to scan your codebase for security risks.

With Cerberus, you can rest assured that your repository is protected from potential security breaches. The combination of regex pattern matching, Shannon entropy calculations, and SARIF integration makes Cerberus a powerful tool in the fight against security risks. 

Cerberus is named after the three-headed dog of Greek mythology that guarded the gates of the Underworld, and is designed to provide a similar level of protection for your repository. By using Cerberus, you can help prevent security breaches and keep your sensitive information safe. 

To get started with Cerberus, simply run the scanner.py script against your local folder, and review the results.sarif file for any potential security risks. You can also integrate Cerberus with your GitHub repository using the provided .github/workflows/cerberus.yml file, allowing for automated security scanning and alerts. 

By using Cerberus, you can help protect your repository from security breaches and ensure the integrity of your sensitive information.