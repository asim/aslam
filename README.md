# Aslam

An Islamic knowledge base for Muslims. [Use Aslam](https://aslam.org).

Read and search the Quran, Hadith, Tafsir Ibn Kathir, Seerah, scholarly Q&A, classical works and adhkar. Learn Quranic Arabic, save notes and bookmarks, and ask questions grounded in the sources.

- Browse reference texts with citations and reading progress.
- Keep chats and notes private, or choose to share them.
- See prayer times and a daily reminder.
- Install the website as a PWA.
- Connect other applications through the [HTTP API](https://aslam.org/api/docs) or [MCP](docs/api.md).

## Run locally

Install Go and a C compiler, then follow the [installation guide](docs/installation.md) to create the database encryption key and configure your environment.

```sh
go build -o aslam .
./aslam
```

Open http://localhost:8000. Configure authentication before exposing the server publicly.

## Documentation

- [Installation and configuration](docs/installation.md)
- [Architecture](docs/architecture.md)
- [API and MCP](docs/api.md)
- [Sources and reader pages](docs/sources.md)
- [Operations](docs/operations.md)
- [All documentation](docs/README.md)
- [Contributor guidance](AGENTS.md)
