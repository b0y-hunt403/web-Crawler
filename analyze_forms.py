import sqlite3
import json
from collections import defaultdict

conn = sqlite3.connect('scanner_discovery.db')
cursor = conn.cursor()

# Get all requests with form fields
cursor.execute("""
    SELECT url, method, form_fields, form 
    FROM discovered_requests 
    WHERE form_fields IS NOT NULL AND form_fields != 'null'
""")

results = cursor.fetchall()

print("=" * 80)
print("FORM ANALYSIS REPORT")
print("=" * 80)

for url, method, fields_json, form_json in results:
    if not fields_json or fields_json == 'null':
        continue
    
    try:
        fields = json.loads(fields_json)
        
        # Determine form type from URL
        form_type = "Unknown"
        if "login" in url.lower():
            form_type = "LOGIN"
        elif "register" in url.lower() or "signup" in url.lower():
            form_type = "REGISTRATION"
        elif "forgot" in url.lower() or "reset" in url.lower():
            form_type = "PASSWORD_RESET"
        elif "contact" in url.lower():
            form_type = "CONTACT"
        
        print(f"\n{'='*60}")
        print(f"FORM: {form_type}")
        print(f"URL: {url}")
        print(f"Method: {method}")
        print(f"Fields: {len(fields)}")
        print("-" * 60)
        
        # Analyze fields
        has_password = False
        has_email = False
        has_username = False
        required_fields = []
        field_types = defaultdict(int)
        
        for field in fields:
            field_name = field.get('name', 'unnamed')
            field_type = field.get('type', 'text')
            required = field.get('required', False)
            placeholder = field.get('placeholder', '')
            
            field_types[field_type] += 1
            
            if required:
                required_fields.append(field_name)
            
            if field_type == 'password':
                has_password = True
            if field_type == 'email' or 'email' in field_name.lower():
                has_email = True
            if 'user' in field_name.lower() or 'name' in field_name.lower():
                has_username = True
            
            # Display field with indicators
            req_indicator = "🔴 REQUIRED" if required else "⚪ optional"
            print(f"  {req_indicator}: {field_name} ({field_type})")
            if placeholder:
                print(f"      placeholder: '{placeholder}'")
        
        print(f"\nField Summary:")
        print(f"  - Total fields: {len(fields)}")
        print(f"  - Required fields: {len(required_fields)}")
        print(f"  - Has password: {'✅' if has_password else '❌'}")
        print(f"  - Has email: {'✅' if has_email else '❌'}")
        print(f"  - Has username: {'✅' if has_username else '❌'}")
        print(f"  - Field types: {dict(field_types)}")
        
        if form_type == "LOGIN":
            print("\n  ⚠️  LOGIN FORM DETECTED")
            if has_password and (has_email or has_username):
                print("  ✅ Complete login form with credentials")
            else:
                print("  ⚠️  Incomplete login form - may be missing fields")
        
        if form_type == "REGISTRATION":
            print("\n  📝 REGISTRATION FORM DETECTED")
            print(f"  {len(fields)} fields to fill")
        
    except Exception as e:
        print(f"Error parsing form at {url}: {e}")

conn.close()

print("\n" + "=" * 80)
print("RECOMMENDATIONS")
print("=" * 80)
print("""
1. Test Login: POST /login with username/email + password
2. Test Registration: POST /register/candidate with all required fields
3. Test Password Reset: POST /forgot-password with email
4. Test Contact Form: POST /contact with name, email, phone, subject, message
5. Check for authentication bypass vulnerabilities
6. Test for SQL injection on all form fields
7. Test for XSS on all input fields
8. Check rate limiting on login/registration endpoints
""")
