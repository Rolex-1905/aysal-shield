import requests   # For sending HTTP requests
from urllib.parse import urlparse

def main():
    print("=" * 50)
    print("SECUDE Security Automation Tool")
    print("=" * 50)

    print("Purpose:")
    print("- Run controlled security checks on approved environments only")
    print("- Focus on safety, stability, and clear reporting")
    print()

    print("Safety Notice:")
    print("- Do NOT run against production systems")
    print("- Non-destructive checks only")
    print("- Explicit permission is required")
    print()

    consent = input("Do you confirm you have permission to run this tool? (yes/no): ").strip().lower()
    if consent != "yes":
        print("\nPermission not confirmed. Exiting safely.")
        return

    print("\nPermission confirmed.")

    # Ask for target URL
    target = input("Enter the target URL for testing (Dev/QA only): ").strip()
    
    # Basic URL validation
    parsed_url = urlparse(target)
    if not parsed_url.scheme or not parsed_url.netloc:
        print("Invalid URL. Exiting safely.")
        return

    print(f"Target set to: {target}")
    print("Status: Tool initialized successfully")

    # Step 1: Check if site is reachable
    try:
        response = requests.get(target, timeout=10)
        print(f"\n[Check] HTTP Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[Error] Could not reach {target}: {e}")

if __name__ == "__main__":
    main()
