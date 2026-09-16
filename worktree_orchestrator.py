#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request
import urllib.error

def make_http_request(url, headers, payload=None):
    try:
        # Include custom User-Agent to bypass Cloudflare header blocking (Error 1010)
        headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        data = json.dumps(payload).encode('utf-8') if payload else None
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        print(f"\n[API ERROR {e.code}] {e.reason}\nDetails: {error_body}\n")
        raise e

def call_gemini(prompt, api_key, model="gemini-3.6-flash"):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    data = make_http_request(url, headers, payload)
    return data["candidates"][0]["content"]["parts"][0]["text"]

def call_groq(prompt, api_key, model="openai/gpt-oss-120b"):
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}]
    }
    data = make_http_request(url, headers, payload)
    return data["choices"][0]["message"]["content"]

def call_openai(prompt, api_key, model="gpt-4o-mini"):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}]
    }
    data = make_http_request(url, headers, payload)
    return data["choices"][0]["message"]["content"]

def call_ollama(prompt, model="llama3", host="http://localhost:11434"):
    url = f"{host}/api/chat"
    headers = {"Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False
    }
    data = make_http_request(url, headers, payload)
    return data["message"]["content"]

def generate_ai_response(provider, prompt, model=None):
    if provider == "gemini":
        key = os.getenv("GEMINI_API_KEY")
        if not key: raise ValueError("GEMINI_API_KEY is not set.")
        return call_gemini(prompt, key, model or "gemini-3.6-flash")
    
    elif provider == "groq":
        key = os.getenv("GROQ_API_KEY")
        if not key: raise ValueError("GROQ_API_KEY is not set.")
        return call_groq(prompt, key, model or "openai/gpt-oss-120b")
    
    elif provider == "openai":
        key = os.getenv("OPENAI_API_KEY")
        if not key: raise ValueError("OPENAI_API_KEY is not set.")
        return call_openai(prompt, key, model or "gpt-4o-mini")
    
    elif provider == "ollama":
        return call_ollama(prompt, model or "llama3")
    
    elif provider == "hybrid":
        gemini_key = os.getenv("GEMINI_API_KEY")
        groq_key = os.getenv("GROQ_API_KEY")
        if not gemini_key or not groq_key:
            raise ValueError("Both GEMINI_API_KEY and GROQ_API_KEY must be set for hybrid mode.")
        
        print("\n -> [Stage 1/2] Draft Generation with Gemini...")
        draft = call_gemini(prompt, gemini_key, "gemini-3.6-flash")
        
        print(" -> [Stage 2/2] Code Review & Refinement with Groq (Llama-3.3-70B)...")
        review_prompt = (
            f"You are a Senior Principal Engineer reviewing code generated for this task: '{prompt}'.\n\n"
            f"Here is the draft implementation:\n\n{draft}\n\n"
            f"Review the draft for bugs, performance issues, missing type hints, or edge cases. "
            f"Provide the final optimized, production-ready code along with a brief breakdown of improvements."
        )
        return call_groq(review_prompt, groq_key, "openai/gpt-oss-120b")

    else:
        raise ValueError(f"Unsupported provider: {provider}")

def run_cmd(cmd, cwd=None):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)
    if res.returncode != 0:
        print(f"[ERROR] Command failed: {cmd}\n{res.stderr}")
    return res.stdout.strip()

def main():
    parser = argparse.ArgumentParser(description="Git Worktree AI Orchestrator")
    parser.add_argument("--prompt", required=True, help="Task description")
    parser.add_argument("--provider", default="gemini", choices=["gemini", "groq", "openai", "ollama", "hybrid"], help="AI provider")
    parser.add_argument("--model", help="Specific model override")
    parser.add_argument("--branch", help="Custom worktree branch name")
    args = parser.parse_args()

    timestamp = int(time.time())
    branch_name = args.branch or f"ai-task-{timestamp}"
    worktree_dir = pathlib.Path.cwd() / ".." / f"worktree-{branch_name}"

    print(f"[1/4] Creating Git worktree for branch '{branch_name}'...")
    run_cmd(f"git worktree add -b {branch_name} {worktree_dir}")

    print(f"[2/4] Querying AI Pipeline ({args.provider.upper()})...")
    try:
        response = generate_ai_response(args.provider, args.prompt, args.model)
        print("\n--- Final Refined Response ---")
        print(response)
        print("------------------------------\n")

        output_file = worktree_dir / "AI_RESPONSE.md"
        output_file.write_text(response)
        print(f"[3/4] Saved response to {output_file}")

    except Exception as e:
        print(f"[ERROR] Pipeline execution failed: {e}")
        sys.exit(1)

    print(f"[4/4] Worktree ready at: {worktree_dir.resolve()}")

if __name__ == "__main__":
    main()

import subprocess
import json
from pathlib import Path

def run_automated_pipeline_step():
    print("🚀 Running automated test and analysis pipeline...")
    
    # 1. Run pytest
    test_result = subprocess.run(
        ["python3", "-m", "pytest", "-v"],
        capture_output=True,
        text=True
    )
    
    print(test_result.stdout)
    
    if test_result.returncode != 0:
        print("❌ Tests failed! Feeding output to term_analyzer...")
        
        # 2. Feed failure output to term_analyzer via its CLI or module
        analyzer_process = subprocess.run(
            ["python3", "-m", "term_analyzer.cli"],
            input=test_result.stdout,
            capture_output=True,
            text=True
        )
        
        print("🔎 Term Analyzer Feedback:")
        print(analyzer_process.stdout)
        return False
    else:
        print("✅ All tests passed successfully!")
        return True

def execute_task_with_feedback(task_prompt: str, max_retries: int = 3):
    print(f"🎯 Starting autonomous task: {task_prompt}")
    
    for attempt in range(max_retries):
        print(f"\n🔄 Pipeline Attempt {attempt + 1} of {max_retries}")
        
        # Run the automated test and analysis check
        success = run_automated_pipeline_step()
        
        if success:
            print("🚀 Verification passed! Task completed successfully.")
            return True
        else:
            if attempt == max_retries - 1:
                print("❌ Max retries reached. Manual intervention required.")
                return False
            
            print("🤖 Feeding analysis feedback back to AI for auto-correction patch...")
            # Placeholder for your model calling function:
            # fix_code_with_ai(task_prompt, last_error_logs)

import os
# Assuming you use google-genai or requests/openai client for Groq/Gemini
from google import genai

def fix_code_with_ai(task_prompt: str, error_logs: str, file_path: str = "term_analyzer/parser.py") -> bool:
    print(f"🤖 Sending error feedback to AI to fix {file_path}...")
    
    # Read the current broken code
    current_code = Path(file_path).read_text()
    
    prompt = f"""
    You are an autonomous AI software developer working in a Termux environment.
    Original Task: {task_prompt}
    
    The code currently fails with these test errors and analyzer feedback:
    {error_logs}
    
    Current file content ({file_path}):
    ```python
    {current_code}
    ```
    
    Please fix the bug. Return ONLY the corrected Python code inside a standard python code block. No extra markdown explanations.
    """
    
    try:
        # Using Gemini API client (ensure GEMINI_API_KEY is set in your environment)
        client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )
        
        raw_text = response.text
        # Extract code block if wrapped in markdown
        if "```python" in raw_text:
            code_block = raw_text.split("```python")[1].split("```")[0].strip()
        elif "```" in raw_text:
            code_block = raw_text.split("```")[1].split("```")[0].strip()
        else:
            code_block = raw_text.strip()
            
        # Overwrite file with the AI-fixed code
        Path(file_path).write_text(code_block)
        print(f"✨ Successfully applied AI patch to {file_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to generate AI patch: {e}")
        return False

import os
from google import genai

def fix_code_with_ai(task_prompt: str, error_logs: str, file_path: str = "term_analyzer/parser.py") -> bool:
    print(f"🤖 Sending error feedback to AI to fix {file_path}...")
    
    current_code = Path(file_path).read_text()
    
    prompt = f"""
    You are an autonomous AI software developer working in a Termux environment.
    Original Task: {task_prompt}
    
    The code currently fails with these test errors and analyzer feedback:
    {error_logs}
    
    Current file content ({file_path}):
    ```python
    {current_code}
    ```
    
    Please fix the bug. Return ONLY the corrected Python code inside a standard python code block. No extra markdown explanations.
    """
    
    try:
        client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )
        
        raw_text = response.text
        if "```python" in raw_text:
            code_block = raw_text.split("```python")[1].split("```")[0].strip()
        elif "```" in raw_text:
            code_block = raw_text.split("```")[1].split("```")[0].strip()
        else:
            code_block = raw_text.strip()
            
        Path(file_path).write_text(code_block)
        print(f"✨ Successfully applied AI patch to {file_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to generate AI patch: {e}")
        return False

def execute_task_with_feedback(task_prompt: str, max_retries: int = 3):
    print(f"🎯 Starting autonomous task: {task_prompt}")
    
    for attempt in range(max_retries):
        print(f"\n🔄 Pipeline Attempt {attempt + 1} of {max_retries}")
        
        test_result = subprocess.run(["python3", "-m", "pytest", "-v"], capture_output=True, text=True)
        if test_result.returncode == 0:
            print("🚀 Verification passed! Task completed successfully.")
            return True
        
        print("❌ Tests failed. Analyzing with term_analyzer...")
        analyzer_process = subprocess.run(["python3", "-m", "term_analyzer.cli"], input=test_result.stdout, capture_output=True, text=True)
        
        feedback = analyzer_process.stdout + "\n" + test_result.stdout
        
        if attempt == max_retries - 1:
            print("❌ Max retries reached. Manual intervention required.")
            return False
            
        fix_code_with_ai(task_prompt, feedback)
