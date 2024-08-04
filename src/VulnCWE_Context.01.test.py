from file_summarizer_assistant import FileSummarizerAssistant  # Import the class
from datetime import datetime

def generate_cwe_question(cwe_name, language):
    return f"Read about {cwe_name} based on the content provided in the files attached. Once you are done, think about the different variations {cwe_name} can occur in a web application written in {language} programing language, especially in different (popular frameworks), keeping in mind the common places these vulnerabilities can be detected such as paramter in the URL, body, header of http requests and the indicators of success from the http response. Explain to an author of a DAST tool detection rules what {cwe_name} is, and for each variation write an OWASP ZAP Zest script to detect those vulnerabilities. The goal is to have a low amount of false negatives and false positives during Web Application Testing. Please note Zest Scripts are in JSON Format, please read the attached documentation to help write effective Zest Scripts."

def main():
    file_summarizer = FileSummarizerAssistant()
    
    languages = ["Java", "PHP", "C#"]
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
