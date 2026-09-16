import os
import sys
import subprocess
import argparse
requests = __import__('requests')

def create_worktree(model_name: str) -> str:
    branch_name = f"feature/{model_name}-solution"
    worktree_path = f"../worktrees/{model_name}"

    subprocess.run(["git", "worktree", "remove", "-f", worktree_path], stderr=subprocess.DEVNULL)
    subprocess.run(["git", "branch", "-D", branch_name], stderr=subprocess.DEVNULL)

    print(f"[*] Creating worktree: {worktree_path} (Branch: {branch_name})")
    subprocess.run(["git", "worktree", "add", "-b", branch_name, worktree_path, "HEAD"], check=True)
    return worktree_path

def get_active_groq_model(headers: dict) -> str:
    url = "https://api.groq.com/openai/v1/models"
    res = requests.get(url, headers=headers)
    if res.status_code != 200:
        raise Exception(f"Failed to list models (HTTP {res.status_code}): {res.text}")
    
    data = res.json().get("data", [])
    excluded_keywords = [
        "whisper", "guard", "audio", "embed", "tts", "safeguard", 
        "orpheus", "canopy", "prompt-guard"
    ]
    chat_models = [
        m["id"] for m in data 
        if not any(keyword in m["id"].lower() for keyword in excluded_keywords)
    ]
    
    if not chat_models:
        raise Exception("No standard chat models found.")
        
    preferred = [
        "llama-3.3-70b-versatile", 
        "llama-3.1-8b-instant", 
        "llama3-8b-8192", 
        "mixtral-8x7b-32768"
    ]
    for model in preferred:
        if model in chat_models:
            return model
            
    return chat_models[0]

def clean_code(text: str) -> str:
    if "```python" in text:
        parts = text.split("```python")
        if len(parts) > 1:
            text = parts[1].split("```")[0]
    elif "```" in text:
        parts = text.split("```")
        if len(parts) > 1:
            text = parts[1].split("```")[0]
    return text.strip()

def query_provider(provider: str, prompt: str) -> tuple:
    if provider == "groq":
        key = os.getenv("GROQ_API_KEY", "").strip()
        if not key or key.startswith("your"):
            raise Exception("GROQ_API_KEY is missing or invalid.")
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        model = get_active_groq_model(headers)
        url = "https://api.groq.com/openai/v1/chat/completions"
    elif provider == "openai":
        key = os.getenv("OPENAI_API_KEY", "").strip()
        if not key or key.startswith("your"):
            raise Exception("OPENAI_API_KEY is missing or invalid.")
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        model = "gpt-4o-mini"
        url = "https://api.openai.com/v1/chat/completions"
    elif provider == "ollama":
        headers = {"Content-Type": "application/json"}
        model = os.getenv("OLLAMA_MODEL", "llama3")
        url = "http://localhost:11434/v1/chat/completions"
    else:
        raise Exception(f"Unknown provider: {provider}")

    print(f"[*] Using Provider: {provider.upper()} (Model: {model})")
    
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system", 
                "content": "You are an expert Python automation developer writing code for Termux on Android (which runs a Linux userland). Your output must be ONLY valid, runnable Python code using standard English Python syntax and standard library modules only (such as reading /proc/meminfo for system stats). Never reject execution based on the platform being Android or Linux. Do not use non-English words for code keywords."
            },
            {
                "role": "user", 
                "content": prompt
            }
        ],
        "max_tokens": 2048
    }
    
    res = requests.post(url, json=payload, headers=headers)
    data = res.json()
    if res.status_code != 200:
        raise Exception(f"HTTP {res.status_code}: {data.get('error', {}).get('message', res.text)}")
    
    raw_content = data["choices"][0]["message"]["content"]
    return model, clean_code(raw_content)

def run_orchestrator(provider: str, prompt: str):
    worktree_path = create_worktree(provider)
    print(f"[*] Querying {provider} with prompt: '{prompt}'")
    try:
        model, code = query_provider(provider, prompt)
        output_file = os.path.join(worktree_path, "solution.py")
        with open(output_file, "w") as f:
            f.write(code)

        print(f"[*] Validating script execution...")
        test_run = subprocess.run(
            [sys.executable, output_file],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if test_run.returncode != 0:
            print(f"[✗] Validation failed! Script exited with code {test_run.returncode}")
            print(f"Error output:\n{test_run.stderr.strip()}")
            raise Exception("Generated code failed automated validation checks.")
        
        print(f"[✓] Validation passed! Output:\n{test_run.stdout.strip()}")

        subprocess.run(["git", "-C", worktree_path, "add", "solution.py"], check=True)
        subprocess.run(["git", "-C", worktree_path, "commit", "-m", f"Add validated solution from {provider} ({model})"], check=True)
        print(f"[✓] Saved and committed solution for {provider}")
        
    except subprocess.TimeoutExpired:
        print(f"[✗] Validation failed: Script execution timed out.")
    except Exception as e:
        print(f"[✗] Failed {provider}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Coder Worktree Orchestrator")
    parser.add_argument("--provider", choices=["groq", "openai", "ollama"], default="groq", help="AI provider to use")
    parser.add_argument("prompt", nargs="+", help="The coding task prompt")
    
    args = parser.parse_args()
    full_prompt = " ".join(args.prompt)
    
    run_orchestrator(args.provider, full_prompt)
