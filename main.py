import secrets
import string
import math

MIN_ENTROPY = 60  # bits

def calculate_entropy(password: str) -> float:
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in string.punctuation for c in password):
        charset += len(string.punctuation)

    if charset == 0:
        return 0

    entropy = len(password) * math.log2(charset)
    return entropy


def is_skeptical_enough(password: str) -> bool:
    if len(password) < 12:
        return False
    if password.lower() == password or password.upper() == password:
        return False
    if password.isalnum():
        return False
    if any(password.count(c) > 2 for c in password):
        return False

    entropy = calculate_entropy(password)
    return entropy >= MIN_ENTROPY


def generate_password(length=16) -> str:
    characters = (
        string.ascii_lowercase +
        string.ascii_uppercase +
        string.digits +
        string.punctuation
    )

    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if is_skeptical_enough(password):
            return password


def main():
    print("🔐 Skeptical Password Generator")
    print("--------------------------------")

    try:
        length = int(input("Enter desired password length (>=12): "))
        if length < 12:
            raise ValueError
    except ValueError:
        print("❌ Invalid input. Using default length = 16.")
        length = 16

    password = generate_password(length)
    entropy = calculate_entropy(password)

    print("\n✅ Generated Password:")
    print(password)
    print(f"\n🔍 Entropy Score: {entropy:.2f} bits")
    print("🛡️ Status: Skeptically Secure")


if __name__ == "__main__":
    main()
