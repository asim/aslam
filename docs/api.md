# API and MCP

Create an account key under [Profile → Developers → API keys](https://aslam.org/profile/api-keys). Send it in the `Authorization: Bearer YOUR_KEY` header. Keys inherit account permissions and model allowances. Keep them out of URLs and browser-side code; revoke unused keys.

The [HTTP reference](https://aslam.org/api/docs) and [OpenAPI document](../internal/discovery/openapi.json) describe methods, inputs and responses. The [agent guide](../internal/discovery/llms.txt) contains collection guidance and citation rules.

## Authentication

| Surface | Access |
| --- | --- |
| `GET /api/knowledge/search` | Public, published reference excerpts only |
| `GET /api/search` | Public entry point; account-aware results when authenticated |
| Knowledge collections, contents, browse and resource endpoints | Account API key or valid browser session |
| Account API: notes, chats, profile and reading progress | Account API key or valid browser session, plus ownership checks |
| `/mcp` | Account API key required |
| `/profile/api-keys` | Browser session only; existing keys cannot mint keys |

Public reader pages remain browsable without a key. Reference retrieval and MCP do not invoke a model or expose personal chats, notes or cached answers.

## Knowledge retrieval

```sh
curl 'https://aslam.org/api/knowledge/search?q=patience&collection=quran&limit=5'

curl -H "Authorization: Bearer $ASLAM_API_KEY" \
  'https://aslam.org/api/knowledge/resource?path=/quran/2/153'
```

Use `/api/knowledge/collections` to discover collections, `contents?collection=...` for chapters/books/categories, and `browse?collection=...` for ordered entries. Follow returned `next` URLs. Browse defaults to 20 results, allows up to 50 and accepts an optional group and offset. Search accepts up to 1,000 UTF-8 bytes in `q` and a limit of 1–50.

Collections include Quran, Bukhari, Names, Tafsir, Seerah, Ghazali, IslamQA, adhkar, Riyad us-Salihin, Arabic words, roots, reading passages and stories. Use the returned resource paths rather than constructing slugs.

For long resources, `read` and the HTTP resource endpoint accept `text_limit` (1–12,000 characters), `text_offset` and `text_field`. Follow `text_page.next` until null; concatenating pages reproduces the selected field exactly. Chat defaults to 12,000-character pages without duplicate HTML.

Read a full passage before quoting. Preserve source attribution and keep scripture, translation, biography and commentary distinct. Invalid inputs return 400; missing or inaccessible resources return 404. See OpenAPI for the full error contract.

## Account actions

The HTTP API covers chats/history/questions, notes and saved links, visibility, reading progress, profile reading and location updates. `/api/chat/send` streams plain text, not SSE, and uses the same model allowance as the website. Reading progress for roots and passages shares the `arabic` source.

## MCP

Connect to `https://aslam.org/mcp` using Streamable HTTP and the Authorization header. The tools are `collections`, `contents`, `browse`, `search` and `read`. Responses are stateless JSON; there is no legacy SSE endpoint. MCP exposes reference retrieval, not personal account actions.

## Discovery and maintenance

`/.well-known/api-catalog`, `/openapi.json` and `/llms.txt` are embedded public documents supporting GET and HEAD. The catalog uses the RFC 9727 Linkset format and links to API descriptions.

When changing endpoints, keep the route handlers, OpenAPI, API catalog, agent guide and `internal/server/html/api_docs.html` consistent. Useful contract checks:

```sh
go test ./internal/discovery ./internal/server -run 'TestDiscoveryRoutes|TestKnowledgeDiscoveryContract'
```
