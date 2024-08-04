from file_summarizer_assistant import FileSummarizerAssistant  # Import the class
from datetime import datetime

def generate_cwe_question(cwe_name, language):
    return f"""
**Task: Create OWASP ZAP Zest Scripts for Detecting {cwe_name} Vulnerabilities in {language} Web Applications**

**Instructions:**

1. **Review and Understand {cwe_name}:** 
   - Read the attached files to gain a thorough understanding of {cwe_name} vulnerabilities.
   - Focus on how this vulnerability typically manifests in web applications written in {language}, especially within popular frameworks.
   - Review ZAP Zest scripting documentation to familiarize yourself with key concepts, such as `ZestRequest`, `ZestAssertion`, `ZestAction`, and `ZestExpression`, which will be essential for scripting.

2. **Identify Variations and Common Injection Points:**
   - Consider the different variations of {cwe_name} that may occur in web applications.
   - Identify common injection points where this vulnerability is likely to appear, such as:
     - URL parameters
     - HTTP request bodies
     - HTTP headers
     - Cookies
     - Query strings
   - Ensure that these variations are addressed in the Zest scripts, with specific focus on areas frequently targeted in {language}-based applications.

3. **Determine Indicators of Success:**
   - Analyze typical HTTP responses and patterns that indicate the presence of {cwe_name}, such as error messages, status codes, or specific response content.
   - Use `ZestAssertion` and `ZestExpression` to verify these indicators within the script.
   - Consider both positive and negative test cases to fine-tune the accuracy of detection.

4. **Write OWASP ZAP Zest Scripts:**
   - Create a Zest script in JSON format for each identified variation of {cwe_name}:
     - Start by defining the `ZestRequest` to simulate the attack vector.
     - Incorporate `ZestAction` elements to manipulate requests or responses as needed.
     - Use `ZestAssertion` to check for expected responses that confirm the presence of the vulnerability.
     - Implement `ZestExpression` to add logic and control flow within the script, handling complex scenarios and variations.
   - Ensure the scripts are structured to minimize false negatives (missed vulnerabilities) and false positives (incorrect detections).
   - Reference the attached Zest documentation to confirm proper usage of scripting constructs and methods.

5. **Documentation and Explanation:**
   - Provide a clear explanation of {cwe_name}, detailing how it can be exploited and its impact on web applications.
   - For each Zest script, explain the logic behind its design, including how it detects specific variations of the vulnerability and the reasoning for chosen injection points and assertions.

**Objective:** The goal is to create precise and reliable Zest scripts that detect {cwe_name} with a low rate of false positives and false negatives, ensuring effective web application security testing.
"""

def main():
    file_summarizer = FileSummarizerAssistant()
    
    languages = ["Java", "PHP"]
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
