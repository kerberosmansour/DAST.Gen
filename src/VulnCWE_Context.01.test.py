from file_summarizer_assistant import FileSummarizerAssistant  # Import the class
from datetime import datetime

def generate_cwe_question(cwe_name, language):
    return f"""
**Task: Create OWASP ZAP Zest Scripts for Detecting {cwe_name} Vulnerabilities in {language} Web Applications**

**Instructions:**

1. **Review and Understand {cwe_name}:** 
   - Read the attached files to understand the nature of {cwe_name} vulnerabilities.
   - Focus on how this vulnerability typically manifests in web applications written in {language}, particularly within popular frameworks.

2. **Identify Variations and Common Injection Points:**
   - Consider the different variations of {cwe_name} that can occur in web applications.
   - Identify common injection points for this vulnerability, such as parameters in the URL, HTTP request bodies, headers, and other relevant areas where these vulnerabilities often appear.

3. **Determine Indicators of Success:**
   - Analyze typical HTTP responses that indicate the presence of {cwe_name}, which will help distinguish successful detections from false positives.

4. **Write OWASP ZAP Zest Scripts:**
   - For each identified variation of {cwe_name}, create an OWASP ZAP Zest script in JSON format that effectively detects the vulnerability.
   - Ensure the scripts are designed to minimize false negatives and false positives during Web Application Testing.
   - Refer to the attached documentation to ensure the Zest scripts are constructed correctly and are effective in identifying the vulnerabilities.

5. **Documentation and Explanation:**
   - Provide a clear explanation of what {cwe_name} is, including how it can be exploited.
   - Detail how each Zest script works, explaining how it detects the specific variations of the vulnerability.

**Objective:** The goal is to create accurate and reliable detection rules for {cwe_name} with a low rate of false positives and false negatives.
"""

def main():
    file_summarizer = FileSummarizerAssistant()
    
    languages = ["C#"]
    cwes = {
        "CWE-917": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
        "CWE-502": "Deserialization of Untrusted Data",
        "CWE-089": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "CWE-078": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "CWE-094": "Improper Control of Generation of Code ('Code Injection')",
        "CWE-843": "Access of Resource Using Incompatible Type ('Type Confusion')",
        "CWE-434": "Unrestricted Upload of File with Dangerous Type",
        "CWE-077": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
        "CWE-427": "Uncontrolled Search Path Element",
        "CWE-611": "Improper Restriction of XML External Entity Reference",
        "CWE-352": "Cross-Site Request Forgery (CSRF)",
        "CWE-190": "Integer Overflow or Wraparound",
        "CWE-022": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "CWE-918": "Server-Side Request Forgery (SSRF)",
        "CWE-059": "Improper Link Resolution Before File Access ('Link Following')",
        "CWE-295": "Improper Certificate Validation",
        "CWE-400": "Uncontrolled Resource Consumption",
        "CWE-319": "Cleartext Transmission of Sensitive Information",
        "CWE-770": "Allocation of Resources Without Limits or Throttling",
        "CWE-079": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    }

    try:
        for language in languages:
            for cwe_id, cwe_name in cwes.items():
                question = generate_cwe_question(cwe_name, language)
                
                # Static file paths
                file_paths = [
                    "KnowledgeBase/Zest_Scripting_Documentation.md",
                    "KnowledgeBase/WSTG.md"
                ]
                
                # Get the summary
                summary = file_summarizer.summarize_files(file_paths, question)
                
                # Define the output markdown file name
                date_str = datetime.now().strftime("%Y-%m-%d")
                output_file = f"{language}_{cwe_id}_{date_str}.md"
                
                # Write the summary to a markdown file
                with open(output_file, 'w') as f:
                    f.write(f"# {cwe_name} ({cwe_id}) in {language}\n\n")
                    f.write(summary)
                    
                print(f"Generated {output_file}")
                
    finally:
        # Clean up resources
        file_summarizer.cleanup()

if __name__ == "__main__":
    main()
