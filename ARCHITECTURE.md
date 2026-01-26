# Aslam Architecture

## Core Principle

The assistant is a single agent with multiple input/output channels. All channels use the same:
- Conversation model (messages in a thread)
- Response generation (Claude + tools)
- Tool execution

## Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Input Channels                          │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│   Web UI    │    API      │   Email     │  Future: WA/SMS  │
│  /chat/*    │  /api/*     │  IMAP poll  │                  │
└──────┬──────┴──────┬──────┴──────┬──────┴────────┬─────────┘
       │             │             │               │
       └─────────────┴──────┬──────┴───────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core Agent                               │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Conversation (db.Message)               │   │
│  │  - User messages (from any channel)                  │   │
│  │  - Assistant responses                               │   │
│  │  - Tool calls and results                            │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │         generateResponse(messages)                   │   │
│  │  - Calls Claude API                                  │   │
│  │  - Handles tool use loop                             │   │
│  │  - Returns final text response                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Tools                             │   │
│  │  fetch, recall, remember, reminder, wikipedia,       │   │
│  │  www, email_check, email_send                        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Output Channels                          │
│  Response sent back via the same channel that received it   │
└─────────────────────────────────────────────────────────────┘
```

## Key Files

| File | Purpose |
|------|---------|
| `main.go` | HTTP handlers, OAuth, `generateResponse()` |
| `email_worker.go` | Email channel (IMAP polling, sends replies) |
| `tools/tools.go` | Tool registry and execution |
| `tools/*.go` | Individual tool implementations |
| `db/db.go` | Persistence (conversations, messages, threads) |

## Adding a New Channel

1. Create a worker/handler that receives input
2. Find or create a conversation for the thread
3. Add the user message: `db.AddMessage(convID, "user", content)`
4. Generate response: `generateResponse(messages)`
5. Save response: `db.AddMessage(convID, "assistant", response)`
6. Send response back via the channel

## Conversation Threading

Each channel maps its native threading to conversations:
- **Chat**: One conversation per chat session
- **Email**: Thread ID (Message-ID/References) → conversation_id via `email_threads` table
- **Future**: WhatsApp thread ID, SMS phone number, etc.

## Why This Matters

- Same prompt, same tools, same behavior across all channels
- Testing one channel tests them all
- New channels are thin adapters, not new agents
- User can start on email, continue on chat (same conversation)
