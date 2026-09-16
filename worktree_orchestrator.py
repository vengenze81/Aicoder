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
        data = json.dumps(payload).encode('utf-8') if payload else None
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        print(f"\n[API ERROR {e.code}] {e.reason}")
        print(f"Details: {error_body}\n")
        raise e

def call_gemini(prompt, api_key, model="gemini-3.6-flash"):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    data = make_http_request(url, headers, payload)
    return data["candidates"][0]["content"]["parts"][0]["text"]

def call_groq(prompt, api_key, model="llama-3.3-70b-versatile"):
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
        if not key:
            raise ValueError("GEMINI_API_KEY environment variable is not set.")
        return call_gemini(prompt, key, model or "gemini-3.6-flash")
    elif provider == "groq":
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise ValueError("GROQ_API_KEY environment variable is not set.")
        return call_groq(prompt, key, model or "llama-3.3-70b-versatile")
    elif provider == "openai":
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise ValueError("OPENAI_API_KEY environment variable is not set.")
        return call_openai(prompt, key, model or "gpt-4o-mini")
    elif provider == "ollama":
        return call_ollama(prompt, model or "llama3")
    else:
        raise ValueError(f"Unsupported provider: {provider}")

def run_cmd(cmd, cwd=None):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)
    if res.returncode != 0:
        print(f"[ERROR] Command failed: {cmd}\n{res.stderr}")
    return res.stdout.strip()

def main():
    parser = argparse.ArgumentParser(description="Git Worktree AI Orchestrator")
    parser.add_argument("--prompt", required=True, help="Task or feature description for AI")
    parser.add_argument("--provider", default="gemini", choices=["gemini", "groq", "openai", "ollama"], help="AI provider")
    parser.add_argument("--model", help="Specific model name (optional)")
    parser.add_argument("--branch", help="Custom branch name for worktree")
    args = parser.parse_args()

    timestamp = int(time.time())
    branch_name = args.branch or f"ai-task-{timestamp}"
    worktree_dir = pathlib.Path.cwd() / ".." / f"worktree-{branch_name}"

    print(f"[1/4] Creating Git worktree for branch '{branch_name}'...")
    run_cmd(f"git worktree add -b {branch_name} {worktree_dir}")

    print(f"[2/4] Querying {args.provider.upper()} API...")
    try:
        response = generate_ai_response(args.provider, args.prompt, args.model)
        print("\n--- AI Response ---")
        print(response)
        print("-------------------\n")

        output_file = worktree_dir / "AI_RESPONSE.md"
        output_file.write_text(response)
        print(f"[3/4] Saved response to {output_file}")

    except Exception as e:
        print(f"[ERROR] Provider request failed: {e}")
        sys.exit(1)

    print(f"[4/4] Worktree ready at: {worktree_dir.resolve()}")

if __name__ == "__main__":
    main()
