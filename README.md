# Hermes Agent — Railway Template

Deploy [Hermes Agent](https://github.com/NousResearch/hermes-agent) on [Railway](https://railway.app) instantly. This template features an ultra-sleek, secure "Hermes Noir" proxy gateway that provides persistent authentication in front of the **Native Hermes Dashboard**.

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/hermes-agent-ai?referralCode=QXdhdr&utm_medium=integration&utm_source=template&utm_campaign=generic)

> Hermes Agent is an autonomous AI agent by [Nous Research](https://nousresearch.com/) that lives on your server, connects to your messaging channels (Telegram, Discord, Slack, etc.), and gets more capable the longer it runs.

## Features

- **Native Dashboard** — Proxies securely into the official, fully-featured Hermes Dashboard.
- **Secure Auth Gateway** — Protects the native dashboard behind a custom, film-grain styled "Hermes Noir" login screen.
- **Auto-Bootstrapping** — The moment you add your API keys via the Native Dashboard, the invisible Python gateway detects the changes and automatically spins up the Hermes agent process in the background.
- **Zero Duplicate Config** — We don't use duplicate setup forms. When Hermes updates their UI, you instantly get the newest features because this template uses an invisible reverse-proxy.

## Getting Started

### 1. Deploy to Railway

1. Click the **Deploy on Railway** button above.
2. Set the `ADMIN_PASSWORD` environment variable (or a random one will be generated and printed to your deployment logs).
3. Railway automatically attaches a **volume** mounted at `/data` (this persists your Hermes configuration, memories, and databases across redeploys).
4. Open your public Railway URL — log in with username `admin` and your password.

### 2. Configure via Native Dashboard

1. Once logged in, you will be teleported straight into the **Native Hermes Dashboard**.
2. Navigate to **CONFIG** or **KEYS** in the top navigation bar.
3. Configure your Default Model (e.g., `google/gemini-flash-1.5`) and your Provider API keys (e.g., Anthropic, OpenAI, OpenRouter).
4. Hit **Save**.
5. The background watcher will automatically detect your valid config and launch the Hermes gateway process instantly. 

### 3. Connect Channels (Telegram is easiest!)

Hermes Agent interacts entirely through messaging channels. 
1. Go to the Native UI's Config panel.
2. Under "Channels", activate Telegram.
3. Open Telegram and message [@BotFather](https://t.me/BotFather).
4. Send `/newbot`, follow the prompts, and paste the **Bot Token** back into the Hermes Dashboard.
5. Message your bot and start interacting with Hermes!

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Web server port (set automatically by Railway) |
| `ADMIN_USERNAME` | `admin` | Gateway login username |
| `ADMIN_PASSWORD` | *(auto-generated)* | Gateway login password — if unset, a random passkey is printed to deployment logs |

All other configurations (LLM provider, model, channels, tools) are natively managed within the Hermes Dashboard.

## Architecture

```
Railway Container
├── Secure Python Gateway (Starlette + Uvicorn)
│   ├── /login       — Hermes Noir film-grain Auth Screen
│   └── /*           — Transparent proxy to the native dashboard
├── hermes dashboard — The native Hermes UI running on loopback
└── hermes gateway   — Automatically managed background agent process
```

The admin server runs on `$PORT` and manages the `hermes gateway` and `hermes dashboard` as child processes. Configuration is stored natively in `/data/.hermes/config.yaml`. 

## Running Locally

```bash
docker build -t hermes-agent .
docker run --rm -it -p 8080:8080 -e PORT=8080 -e ADMIN_PASSWORD=changeme -v hermes-data:/data hermes-agent
```

Open `http://localhost:8080` and log in with `admin` / `changeme`.

## Credits

- [Hermes Agent](https://github.com/NousResearch/hermes-agent) by [Nous Research](https://nousresearch.com/)
