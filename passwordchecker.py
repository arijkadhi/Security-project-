import re
import string
import getpass 

# Configuration Constants

min_length = 12 
upper = True
lower = True
digits = True

symbol = True

complexity = sum([upper, lower, digits, symbol])


common_pass = {
    "password", "123456", "123456789", "qwerty", "12345", "12345678",
    "111111", "123123", "password123", "p@ssword", "admin", "user",
    
}

# Common keyboard sequences 
sequences = [
    "azerty", "qsdfg", "wxcvb", "12345", "23456", "34567", "45678", "56789", "01234",
"aqwxs", "edcrfv", "1aqw", "2wsx", "3edc",
"98765", "87654", "76543", "65432", "54321", "09876",
"poiuy", "lkjhg", ",nbvc"

]


# Detects 4 or more identical consecutive characters 
max_consecutive_repeats = 3 

# Functions for Checks

def check_length(password):
    """Checks if the password meets the minimum length requirement."""
    if len(password) >= min_length:
        return True, None
    else:
        return False, f"Password is too short (minimum {min_length} characters required)."

def check_complexity(password):
    """Checks if the password meets the required character type complexity."""
    has_upper = re.search(r'[A-Z]', password) is not None
    has_lower = re.search(r'[a-z]', password) is not None
    has_digit = re.search(r'[0-9]', password) is not None
    # symbols
    has_symbol = re.search(r'[!@#$%^&*()-_=+\[\]{};:\'",.<>/?\\|~`]', password) is not None

    complexity_score = sum([has_upper, has_lower, has_digit, has_symbol])
    missing_types = []

    if upper and not has_upper:
        missing_types.append("uppercase letters (A-Z)")
    if lower and not has_lower:
        missing_types.append("lowercase letters (a-z)")
    if digits and not has_digit:
        missing_types.append("digits (0-9)")
    if symbol and not has_symbol:
        missing_types.append("symbols (e.g., !@#$%)")

    # Check if enough types are present 
    required_types_present = True
    if upper and not has_upper: required_types_present = False
    if lower and not has_lower: required_types_present = False
    if digits and not has_digit: required_types_present = False
    if symbol and not has_symbol: required_types_present = False

    if required_types_present:
        return True, None
    else:
        return False, f"Password must include: {', '.join(missing_types)}."

def check_against_context(password, context_info):
    """Checks if the password contains significant parts of contextual information ( username for example)."""
    if not context_info:
        return True, None 

    pwd_lower = password.lower()
    for info in context_info:
        if not info or len(info) < 3: # Ignore empty or very short context strings
            continue
        if info.lower() in pwd_lower:
            return False, f"Password should not contain significant parts of your username or related info ('{info}')."   

    return True, None

def check_common_passwords(password):
    """Checks if the password is in the list of the common passwords."""
    if password.lower() in common_pass:
        return False, "Password is too common."
    else:
        return True, None

def check_sequences(password):
    """Checks for common keyboard or number sequences."""
    pwd_lower = password.lower()
    for seq in sequences:
        if seq in pwd_lower:
            return False, f"Password contains a common sequence ('{seq}')."
        
    return True, None

def check_repetitions(password):
    """Checks for heavily repeated characters."""
    if re.search(r'(.)\1{' + str(max_consecutive_repeats) + r',}', password):
        return False, f"Password contains {max_consecutive_repeats + 1} or more identical consecutive characters."
    else:
        return True, None

# Main Validation

def check_password_strength(password, username=None):
   
    if not password:
         return {
            'verdict': 'Weak',
            'feedback': ["Password cannot be empty."],
            'passed_checks': 0,
            'total_checks': 6 
        }

    context_info = []
    if username:
        context_info.append(username)



    checks = [
        check_length(password),
        check_complexity(password),
        check_against_context(password, context_info),
        check_common_passwords(password),
        check_sequences(password),
        check_repetitions(password),
    ]

    failures = []
    passed_count = 0
    for passed, message in checks:
        if passed:
            passed_count += 1
        elif message:
            failures.append(message)

    verdict = "Strong" if not failures else "Weak"

    # Provide a final  message 
    if verdict == "Strong":
        final_message = "✅"
        feedback_list = [] 
    else:
        final_message = f"❌"
        feedback_list = failures # List the reasons

    return {
        'verdict': verdict,
        'verdict_message': final_message, 
        'feedback': feedback_list,
        'passed_checks': passed_count,
        'total_checks': len(checks)
    }

#  Command-Line Interface 

if __name__ == "__main__":
    print("--- Password Strength Tester ---")
   

    
    password_to_test = getpass.getpass("Enter the password to test: ")
    username_context = input("Enter username (optional, press Enter to skip): ")

    if not username_context:
        username_context = None

    result = check_password_strength(password_to_test, username_context)

    print("\n--- Assessment ---")
    print(result['verdict_message'])
    if result['verdict'] == "Weak":
        print("Reasons:")
        for item in result['feedback']:
            print(f"- {item}")

    print(f"\nChecks Passed: {result['passed_checks']} / {result['total_checks']}")

   
    if result['verdict'] == "Strong":
         print("Good job creating a  strong password!")
    else:
         print("Please try creating a stronger password .")