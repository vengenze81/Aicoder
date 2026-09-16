#!/data/data/com.termux/files/usr/bin/bash

# Ensure output directory exists
mkdir -p ../worktrees

# Check for required API keys
if [ -z "$DEEPSEEK_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "[!] Warning: No API keys found in environment."
    echo "    Run: export DEEPSEEK_API_KEY='your_key'"
    echo "    Run: export ANTHROPIC_API_KEY='your_key'"
    echo ""
fi

echo "[*] Launching Multi-AI Orchestrator..."
python worktree_orchestrator.py
