import os
from dotenv import load_dotenv
from openai import OpenAI

def load_api_key_from_env():
    """
    Load OpenAI API key from .env file
    """
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("API_KEY")

    if not api_key:
        print("❌ No OpenAI API key found in .env file.")
        print("Please add this line to your .env file:")
        print("OPENAI_API_KEY=your_actual_key_here")
        return None

    return api_key


def test_api_key_format(api_key):
    """
    Basic validation of key format
    """
    if not api_key:
        print("❌ API key is empty")
        return False

    if not api_key.startswith("sk-"):
        print("⚠️ API key format may be incorrect (should start with 'sk-')")
        return False

    print("✅ API key format looks correct")
    return True


def test_openai_basic(api_key):
    """
    Basic test: make a small completion call
    """
    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Say 'Hello World' in a creative way"}]
        )
        text = response.choices[0].message.content.strip()
        print("✅ API call succeeded!")
        print(f"Response: {text}")
        return True
    except Exception as e:
        print(f"❌ API Error: {e}")
        return False


def test_openai_comprehensive(api_key):
    """
    Comprehensive test with multiple queries
    """
    try:
        client = OpenAI(api_key=api_key)
        tests_passed = 0
        total_tests = 3

        prompts = [
            "Explain AI in 1 sentence.",
            "Give a creative 5-word story.",
            "List 3 use-cases of OpenAI models."
        ]

        for i, prompt in enumerate(prompts, start=1):
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}]
            )
            text = response.choices[0].message.content.strip()
            if text:
                print(f"✅ Test {i} passed")
                tests_passed += 1
            else:
                print(f"❌ Test {i} failed")

        print(f"\n📊 Test Results: {tests_passed}/{total_tests} tests passed")
        return tests_passed == total_tests

    except Exception as e:
        print(f"❌ Comprehensive test failed: {e}")
        return False


def create_env_template():
    """
    Create a .env template if not exists
    """
    env_file = ".env"
    if not os.path.exists(env_file):
        with open(env_file, "w") as f:
            f.write("# OpenAI API Configuration\n")
            f.write("OPENAI_API_KEY=your_actual_api_key_here\n\n")
        print("📁 Created .env template. Add your actual OpenAI API key.")
    else:
        print("📁 .env file already exists.")


def main():
    create_env_template()

    api_key = load_api_key_from_env()
    if not api_key:
        print("\nPlease add your OpenAI key in .env and rerun.")
        return

    print("\n" + "="*50)
    print("Testing OpenAI API Key...")
    print("="*50)
    print(f"API Key: {api_key[:8]}...{api_key[-4:]}")

    # Step 1: Validate format
    print("\n1. Testing key format...")
    valid_format = test_api_key_format(api_key)

    # Step 2: Basic connectivity
    print("\n2. Testing API connectivity...")
    basic_test = test_openai_basic(api_key)

    # Step 3: Comprehensive tests
    print("\n3. Running comprehensive tests...")
    full_test = test_openai_comprehensive(api_key)

    print("\n" + "="*50)
    print("FINAL RESULTS:")
    print("="*50)
    print(f"Format validation: {'✅' if valid_format else '❌'}")
    print(f"API connectivity: {'✅' if basic_test else '❌'}")
    print(f"Comprehensive tests: {'✅' if full_test else '❌'}")

    if valid_format and basic_test and full_test:
        print("\n🎉 ALL TESTS PASSED! Your OpenAI key works perfectly.")
    else:
        print("\n⚠️ Some tests failed. Please recheck your key or network.")


if __name__ == "__main__":
    main()
