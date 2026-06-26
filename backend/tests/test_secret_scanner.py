import pytest
from app.scanners.secret_scanner import run, Finding

def test_secret_scanner_critical_key():
    files = {
        "config.py": 'GEMINI_API_KEY = "AIzaSyDUMMY_KEY"\nOPENAI_API_KEY = "sk-proj-dummy"\n'
    }
    findings = run(files)
    assert len(findings) == 2
    assert all(f.category == "Secret Exposure Risk" for f in findings)
    assert all(f.severity == "Critical" for f in findings)
    assert any("GEMINI_API_KEY" in f.title for f in findings)
    assert any("OPENAI_API_KEY" in f.title for f in findings)

def test_secret_scanner_high_key():
    files = {
        "settings.py": 'API_KEY = "some-key"\nJWT_SECRET = "jwt-secret-token"\n'
    }
    findings = run(files)
    assert len(findings) == 2
    assert all(f.category == "Secret Exposure Risk" for f in findings)
    assert all(f.severity == "High" for f in findings)

def test_secret_scanner_value_prefix():
    files = {
        "auth.py": 'my_secret = "sk-12345"\ngoogle_token = "AIza6789"\n'
    }
    findings = run(files)
    assert len(findings) == 2
    assert all(f.category == "Secret Exposure Risk" for f in findings)
    assert all(f.severity == "Critical" for f in findings)

def test_secret_scanner_ignore_getenv():
    files = {
        "safe_config.py": (
            'GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")\n'
            'JWT_SECRET = os.environ.get("JWT_SECRET")\n'
            'API_KEY = os.environ["API_KEY"]\n'
        )
    }
    findings = run(files)
    assert len(findings) == 0

def test_secret_scanner_env_file():
    files = {
        ".env": "DB_PASS=secret\n"
    }
    findings = run(files)
    assert len(findings) == 1
    assert findings[0].category == "Secret Exposure Risk"
    assert findings[0].severity == "High"
    assert ".env file committed" in findings[0].title

def test_secret_scanner_system_prompt_file():
    files = {
        "prompts/SYSTEM_PROMPT.txt": "Be a helpful assistant."
    }
    findings = run(files)
    assert len(findings) == 1
    assert findings[0].category == "Prompt Injection Risk"
    assert findings[0].severity == "Medium"

def test_secret_scanner_prompt_concatenation():
    files = {
        "agent.py": (
            'prompt = "Hello " + user_input\n'
            'message = f"User said: {user_input}"\n'
            'query = prompt + " suffix"\n'
        )
    }
    findings = run(files)
    # The concatenation checks might yield findings for each line that does concat
    assert len(findings) > 0
    assert all(f.category == "Prompt Injection Risk" for f in findings)
    assert all(f.severity == "Medium" for f in findings)
