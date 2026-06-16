## LLM Configuration

Blitz uses an OpenAI-compatible chat-completions interface. Any provider can be used if it supports:

```text
POST /v1/chat/completions
choices[0].message.content
```

Ollama on the SIFT machine:

```bash
export LLM_PROVIDER=ollama
export LLM_BASE_URL=http://127.0.0.1:11434/v1
export LLM_API_KEY=ollama
export LLM_MODEL=llama3.2:1b
```

Ollama on a host reachable from SIFT:

```bash
export LLM_PROVIDER=ollama
export LLM_BASE_URL=http://192.168.88.1:11434/v1
export LLM_API_KEY=ollama
export LLM_MODEL=llama3.2:1b
```

Online OpenAI-compatible provider:

```bash
export LLM_PROVIDER=openai-compatible
export LLM_BASE_URL=https://api.openai.com/v1
export LLM_API_KEY="<your api key>"
export LLM_MODEL="<your chosen chat model>"
```

Recommended bounds:

```bash
export LLM_TIMEOUT_SECONDS=600
export LLM_MAX_TOKENS=800
export LLM_RESPONSE_FORMAT_JSON=1
```

Start Ollama:

```bash
ollama serve
```

Start Ollama for network access:

```bash
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

Check Ollama:

```bash
ollama list
curl -sS --max-time 10 http://127.0.0.1:11434/api/tags | python3 -m json.tool
curl -sS --max-time 10 http://127.0.0.1:11434/v1/models | python3 -m json.tool
```

Stop Ollama:

```bash
pkill -f 'ollama serve'
```

If Ollama is a service:

```bash
sudo systemctl start ollama
sudo systemctl status ollama --no-pager
sudo systemctl stop ollama
```

LLM fail-safe:

- If LLM preflight fails, fix the LLM or run the no-LLM command.
- If bounded LLM reasoning fails after deterministic analysis, Blitz records the issue and continues deterministic reporting when possible.
- Review `findings/llm_report_verification.json` to confirm whether LLM reasoning ran and whether it stayed within evidence-backed summaries.
