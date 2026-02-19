# Solo Enterprise for AgentGateway - Security Architecture Diagrams
- [Solo Enterprise for AgentGateway - Security Architecture Diagrams](#solo-enterprise-for-agentgateway---security-architecture-diagrams)
  - [1. Security Options Overview](#1-security-options-overview)
  - [2. CORS - Cross-Origin Resource Sharing](#2-cors---cross-origin-resource-sharing)
  - [3. CSRF - Cross-Site Request Forgery Protection](#3-csrf---cross-site-request-forgery-protection)
  - [4. Basic Authentication (Native)](#4-basic-authentication-native)
  - [5. API Key Authentication (Native)](#5-api-key-authentication-native)
  - [6. External Auth - BYO (Bring Your Own) External Auth Service](#6-external-auth---byo-bring-your-own-external-auth-service)
  - [7. OAuth - Authorization Code Flow (OIDC)](#7-oauth---authorization-code-flow-oidc)
  - [8. OAuth - Access Token Validation](#8-oauth---access-token-validation)
  - [9. JWT Authentication (Native - No ExtAuth)](#9-jwt-authentication-native---no-extauth)
    - [Multi-Provider Support](#multi-provider-support)
  - [10. On-Behalf-Of (OBO) Token Exchange](#10-on-behalf-of-obo-token-exchange)
    - [Token Exchange Architecture](#token-exchange-architecture)
  - [11. Elicitations - Credential Gathering for Upstream APIs](#11-elicitations---credential-gathering-for-upstream-apis)
    - [Elicitation Lifecycle](#elicitation-lifecycle)
  - [12. Combined Security Architecture - End-to-End Deployment View](#12-combined-security-architecture---end-to-end-deployment-view)
  - [Quick Reference: Which Security Option to Use](#quick-reference-which-security-option-to-use)

## 1. Security Options Overview

The following diagram shows the full landscape of security controls available in Solo Enterprise for AgentGateway. Each subsequent section dives deeper into individual flows.

```mermaid
graph TB
    subgraph Clients["Client Layer"]
        Browser["Browser / Web App"]
        Agent["AI Agent / Service"]
        MCP_Client["MCP Client"]
    end

    subgraph AGW["Solo Enterprise for AgentGateway"]
        direction TB
        GW["Gateway Proxy<br/>(Rust-based)"]

        subgraph BrowserSec["Browser Security"]
            CORS["CORS Policy"]
            CSRF["CSRF Protection"]
        end

        subgraph NativeAuthN["Native Authentication (Built-in)"]
            JWT_Auth["JWT Authentication"]
            BasicAuth["Basic Auth"]
            APIKey["API Key Auth"]
        end

        subgraph ExtAuthN["External Auth Service"]
            OAuth_AC["OAuth Authorization Code"]
            OAuth_AT["OAuth Access Token<br/>Validation"]
            BYO["BYO Ext Auth Service"]
        end

        subgraph TokenExchange["Token Exchange (STS)"]
            OBO["On-Behalf-Of<br/>Token Exchange"]
            Elicit["Elicitations<br/>(Credential Gathering)"]
        end
    end

    subgraph IdPs["Identity Providers"]
        Keycloak["Keycloak / OIDC IdP"]
        ExtOAuth["External OAuth Provider<br/>(e.g., GitHub)"]
    end

    subgraph Backends["Backend Services"]
        LLM["LLM Providers<br/>(OpenAI, Anthropic, etc.)"]
        MCP_Server["MCP Tool Servers"]
        AgentBackend["AI Agents"]
        HTTPWorkload["HTTP Workloads<br/>(Non-agentic)"]
    end

    Browser --> CORS & CSRF
    CORS & CSRF --> GW
    Agent --> GW
    MCP_Client --> GW

    GW --> JWT_Auth & BasicAuth & APIKey
    GW --> OAuth_AC & OAuth_AT & BYO
    GW --> OBO & Elicit

    JWT_Auth -.->|JWKS| Keycloak
    OAuth_AC -.->|OIDC| Keycloak
    OAuth_AT -.->|OIDC| Keycloak
    OBO -.->|Subject Token Validation| Keycloak
    Elicit -.->|OAuth Flow| ExtOAuth

    GW --> LLM & MCP_Server & AgentBackend & HTTPWorkload
```

---

## 2. CORS - Cross-Origin Resource Sharing

> **Docs:** [CORS](https://docs.solo.io/agentgateway/2.1.x/security/cors/)

CORS policies control which web origins can interact with AgentGateway-protected resources. Configured via **HTTPRoute filters** or **EnterpriseAgentgatewayPolicy**.

```mermaid
sequenceDiagram
    participant B as Browser (JavaScript)
    participant AGW as AgentGateway Proxy
    participant Backend as Backend Service<br/>(LLM / MCP / Agent)

    Note over B,Backend: CORS Preflight Flow

    B->>AGW: OPTIONS /api (Preflight)<br/>Origin: https://app.example.com
    AGW->>AGW: Check origin against<br/>allowOrigins list

    alt Origin Allowed
        AGW-->>B: 200 OK<br/>access-control-allow-origin: https://app.example.com<br/>access-control-allow-methods: GET, POST, OPTIONS<br/>access-control-allow-headers: Authorization, Content-Type<br/>access-control-max-age: 86400
        B->>AGW: POST /api (Actual Request)<br/>Origin: https://app.example.com<br/>Authorization: Bearer <token>
        AGW->>Backend: Forward request
        Backend-->>AGW: Response
        AGW-->>B: Response + CORS headers
    else Origin NOT Allowed
        AGW-->>B: 200 OK (no CORS headers)<br/>Browser blocks the response
        Note over B: Browser denies access<br/>to response data
    end
```

---

## 3. CSRF - Cross-Site Request Forgery Protection

> **Docs:** [CSRF](https://docs.solo.io/agentgateway/2.1.x/security/csrf/)

CSRF protection validates that the `Origin` header of incoming requests matches the destination to block forged requests from malicious sites.

```mermaid
sequenceDiagram
    participant Attacker as Malicious Site<br/>(attacker.com)
    participant User as User's Browser
    participant AGW as AgentGateway Proxy
    participant Backend as Backend Service

    Note over Attacker,Backend: CSRF Attack Attempt

    Attacker->>User: Trick user into visiting<br/>malicious page with hidden form
    User->>AGW: POST /api/action<br/>Origin: malicioussite.com<br/>Cookie: session=abc123

    AGW->>AGW: CSRF validation:<br/>Origin (malicioussite.com)<br/>vs Destination (api.example.com)

    alt Origin does NOT match destination<br/>and NOT in additionalOrigins
        AGW-->>User: 403 Forbidden<br/>"CSRF validation failed"
        Note over User,AGW: Attack blocked
    end

    Note over User,Backend: Legitimate Request

    User->>AGW: POST /api/action<br/>Origin: allowThisOne.example.com<br/>Cookie: session=abc123

    AGW->>AGW: CSRF validation:<br/>Origin in additionalOrigins list
    AGW->>Backend: Forward request
    Backend-->>AGW: 200 OK
    AGW-->>User: 200 OK
```

---

## 4. Basic Authentication (Native)

> **Docs:** [Basic auth](https://docs.solo.io/agentgateway/2.1.x/security/extauth/basic/)

Basic auth is built into the AgentGateway proxy. It sends base64-encoded `username:password` credentials in the `Authorization` header. The proxy validates against APR1-hashed passwords configured directly in the policy. **No external auth service is required.**

```mermaid
sequenceDiagram
    participant C as Client / Agent
    participant AGW as AgentGateway Proxy
    participant Backend as Backend<br/>(LLM / MCP / Agent / HTTP)

    C->>AGW: POST /api<br/>(no credentials)

    AGW->>AGW: Basic auth check:<br/>No Authorization header found

    AGW-->>C: 401 Unauthorized<br/>"no basic authentication credentials found"

    Note over C,Backend: Retry with credentials

    C->>AGW: POST /api<br/>Authorization: Basic dXNlcjpwYXNzd29yZA==

    AGW->>AGW: Decode base64 → user:password
    AGW->>AGW: Lookup user in policy config
    AGW->>AGW: Verify APR1 hash<br/>(salt + hashed password)

    alt mode: Strict — Credentials valid
        AGW->>Backend: Forward request
        Backend-->>AGW: Response
        AGW-->>C: 200 OK + Response
    else Credentials invalid
        AGW-->>C: 401 Unauthorized
    end

    Note over C,Backend: Optional Mode

    opt
        Note over AGW: mode: Optional<br/>• Valid credentials → forward<br/>• Invalid credentials → 401 reject<br/>• No credentials → allow through
    end
```

---

## 5. API Key Authentication (Native)

> **Docs:** [API key auth](https://docs.solo.io/agentgateway/2.1.x/security/extauth/apikey/)

API key auth is built into the AgentGateway proxy. API keys are long-lived UUIDs stored as Kubernetes Secrets. The proxy validates the API key from the `Authorization` header directly against the referenced secrets. **No external auth service is required.**

```mermaid
sequenceDiagram
    participant C as Client / Agent
    participant AGW as AgentGateway Proxy
    participant K8s as K8s Secrets<br/>(API Keys)
    participant Backend as Backend<br/>(LLM / MCP / Agent / HTTP)

    C->>AGW: POST /api<br/>(no Authorization header)

    AGW->>AGW: API key auth check:<br/>No API key found

    AGW-->>C: 401 Unauthorized<br/>"no API Key found"

    Note over C,Backend: Retry with API key

    C->>AGW: POST /api<br/>x-api-key: N2YwMDIx...

    AGW->>K8s: Lookup referenced secret<br/>(by name or label selector)
    K8s-->>AGW: Secret found

    AGW->>AGW: Compare API key from<br/>request header vs secret

    alt mode: Strict — Key valid
        AGW->>Backend: Forward request
        Backend-->>AGW: Response
        AGW-->>C: 200 OK + Response
    else Key invalid
        AGW-->>C: 401 Unauthorized
    end

    Note over C,Backend: Optional Mode

    opt
        Note over AGW: mode: Optional<br/>• Valid API key → forward<br/>• Invalid API key → 401 reject<br/>• No API key → allow through
    end
```

---

## 6. External Auth - BYO (Bring Your Own) External Auth Service

> **Docs:** [BYO ext auth service](https://docs.solo.io/agentgateway/2.1.x/security/extauth/byo-ext-auth-service/)

Integrate any custom gRPC-based external authorization service with AgentGateway. The gateway delegates auth decisions to your service.

```mermaid
sequenceDiagram
    participant C as Client / Agent
    participant AGW as AgentGateway Proxy
    participant BYO as Your Ext Auth Service<br/>(gRPC)
    participant Backend as Backend<br/>(LLM / MCP / Agent / HTTP)

    C->>AGW: Request to protected route

    AGW->>BYO: gRPC Authorization Request<br/>(headers, path, method)

    BYO->>BYO: Custom authorization logic<br/>(check headers, tokens,<br/>database lookups, etc.)

    alt Authorized
        BYO-->>AGW: ALLOW<br/>(optional: inject headers)
        AGW->>Backend: Forward request
        Backend-->>AGW: Response
        AGW-->>C: 200 OK + Response
    else Not Authorized
        BYO-->>AGW: DENY<br/>(status code, message)
        AGW-->>C: 403 Forbidden<br/>"denied by ext_authz"
    end
```

---

## 7. OAuth - Authorization Code Flow (OIDC)

> **Docs:** [About OAuth](https://docs.solo.io/agentgateway/2.1.x/security/extauth/oauth/about/) | [Authorization Code](https://docs.solo.io/agentgateway/2.1.x/security/extauth/oauth/authorization-code/) | [Keycloak setup](https://docs.solo.io/agentgateway/2.1.x/security/extauth/oauth/keycloak/)

For browser-based / interactive access. The gateway intercepts unauthenticated requests, redirects to the IdP for login, exchanges the authorization code for tokens, and stores a session cookie.

```mermaid
sequenceDiagram
    participant U as User (Browser)
    participant AGW as AgentGateway Proxy
    participant EA as Ext Auth Service
    participant IdP as OIDC IdP<br/>(e.g., Keycloak)
    participant Redis as Redis<br/>(Session Store)
    participant LLM as LLM Provider

    U->>AGW: GET /openai (no session cookie)
    AGW->>EA: Check auth
    EA-->>AGW: No valid session

    AGW-->>U: 302 Redirect → IdP login URL<br/>/realms/master/protocol/openid-connect/auth<br/>?client_id=...&redirect_uri=...&response_type=code&scope=email+openid

    U->>IdP: User visits login page
    U->>IdP: Enter credentials (user1 / password)
    IdP->>IdP: Authenticate user

    IdP-->>U: 302 Redirect → callback URL<br/>/openai?code=AUTH_CODE&state=...

    U->>AGW: GET /openai?code=AUTH_CODE
    AGW->>EA: Exchange authorization code
    EA->>IdP: POST /token<br/>(code + client_id + client_secret)
    IdP-->>EA: ID Token + Access Token

    EA->>Redis: Store session<br/>(keycloak-session cookie)
    EA-->>AGW: Authenticated ✓<br/>Set-Cookie: keycloak-session=...

    AGW-->>U: Set-Cookie + redirect to /openai

    Note over U,LLM: Subsequent Requests

    U->>AGW: POST /openai<br/>Cookie: keycloak-session=...
    AGW->>EA: Validate session
    EA->>Redis: Lookup session
    Redis-->>EA: Valid session + tokens
    EA-->>AGW: Authenticated ✓<br/>(forward JWT as header)
    AGW->>LLM: Forward request
    LLM-->>AGW: Response
    AGW-->>U: 200 OK + Response
```

---

## 8. OAuth - Access Token Validation

> **Docs:** [Access Token Validation](https://docs.solo.io/agentgateway/2.1.x/security/extauth/oauth/access-token/)

For programmatic/API access. The client obtains an access token from the IdP out-of-band and includes it in requests. The gateway validates the token signature using JWKS.

```mermaid
sequenceDiagram
    participant C as Client / Agent
    participant IdP as OIDC IdP<br/>(e.g., Keycloak)
    participant AGW as AgentGateway Proxy
    participant EA as Ext Auth Service
    participant LLM as LLM Provider

    Note over C,IdP: Step 1: Client obtains token out-of-band

    C->>IdP: POST /token<br/>(client_credentials or password grant)<br/>client_id, client_secret, username, password
    IdP-->>C: Access Token (JWT)<br/>(iss, aud, exp, scopes)

    Note over C,LLM: Step 2: Client calls AgentGateway with token

    C->>AGW: POST /openai<br/>Authorization: Bearer <access_token>
    AGW->>EA: Validate token

    EA->>EA: JWT Validation:<br/>1. Verify RS256 signature (JWKS)<br/>2. Check issuer (iss)<br/>3. Check audience (aud)<br/>4. Check expiration (exp)

    alt Token Valid
        EA-->>AGW: Authenticated ✓
        AGW->>LLM: Forward request<br/>(AGW injects LLM API key)
        LLM-->>AGW: Response
        AGW-->>C: 200 OK + Response
    else Token Invalid or Expired
        EA-->>AGW: 403 Forbidden
        AGW-->>C: 403 Forbidden<br/>"external authorization failed"
    end
```

---

## 9. JWT Authentication (Native - No ExtAuth)

> **Docs:** [About JWT auth](https://docs.solo.io/agentgateway/2.1.x/security/jwt/about/) | [Set up JWT auth](https://docs.solo.io/agentgateway/2.1.x/security/jwt/setup/)

AgentGateway supports native JWT validation directly at the proxy layer (without the Ext Auth service). Supports remote JWKS with auto-rotation and multiple providers.

```mermaid
sequenceDiagram
    participant C as Client / Agent
    participant AGW as AgentGateway Proxy
    participant JWKS as JWKS Endpoint<br/>(IdP, e.g., Keycloak)
    participant Backend as Backend Service<br/>(LLM / MCP / Agent)

    Note over AGW,JWKS: Startup: Proxy fetches & caches JWKS

    AGW->>JWKS: GET /realms/master/protocol/<br/>openid-connect/certs
    JWKS-->>AGW: JWKS response (public keys)<br/>Cached for cacheDuration (e.g., 5m)

    Note over C,Backend: Request Flow

    C->>AGW: POST /api<br/>Authorization: Bearer <JWT>

    AGW->>AGW: Extract JWT from Bearer header
    AGW->>AGW: Read kid from JWT header
    AGW->>AGW: Match kid → cached public key
    AGW->>AGW: Verify signature (RS256)
    AGW->>AGW: Validate claims:<br/>• issuer (iss)<br/>• audience (aud) [optional]<br/>• expiration (exp)

    alt mode: Strict — Valid JWT required
        AGW->>Backend: Forward request
        Backend-->>AGW: Response
        AGW-->>C: 200 OK

    else mode: Strict — No JWT or invalid
        AGW-->>C: 401 Unauthorized<br/>"no bearer token found"
    end

    Note over C,Backend: Optional & Permissive Modes

    opt
        Note over AGW: mode: Optional<br/>• Valid JWT → forward<br/>• Invalid JWT → 401 reject<br/>• No JWT → allow through

        Note over AGW: mode: Permissive<br/>• Valid JWT → forward<br/>• Invalid JWT → allow through<br/>• No JWT → allow through
    end
```

### Multi-Provider Support

```mermaid
graph LR
    subgraph AGW["AgentGateway Proxy"]
        JWT["JWT Authentication<br/>(EnterpriseAgentgatewayPolicy)"]
    end

    subgraph Providers["Configured JWT Providers"]
        P1["Provider 1: Keycloak<br/>issuer: keycloak/realms/master<br/>audiences: [my-app]<br/>JWKS: remote"]
        P2["Provider 2: Auth0<br/>issuer: auth0.example.com<br/>audiences: [my-other-app]<br/>JWKS: remote"]
        P3["Provider 3: Custom<br/>issuer: custom-idp.internal<br/>JWKS: inline"]
    end

    JWT --> P1
    JWT --> P2
    JWT --> P3

    Note["Token's iss claim determines<br/>which provider validates it"]

```

---

## 10. On-Behalf-Of (OBO) Token Exchange

> **Docs:** [About OBO and elicitations](https://docs.solo.io/agentgateway/2.1.x/security/obo-elicitations/about/) | [OBO token exchange](https://docs.solo.io/agentgateway/2.1.x/security/obo-elicitations/obo/)

OBO token exchange (RFC 8693) enables agents to act on behalf of users by exchanging the user's JWT for a delegated token that includes both user and agent identities.

```mermaid
sequenceDiagram
    participant U as User
    participant A as AI Agent
    participant STS as AgentGateway STS<br/>(Token Exchange Server<br/>port 7777)
    participant IdP as OIDC IdP<br/>(e.g., Keycloak)
    participant AGW as AgentGateway Proxy
    participant MCP as MCP Tool Server

    Note over U,MCP: Step 1: User authenticates and calls agent

    U->>IdP: Authenticate (login)
    IdP-->>U: OAuth Access Token (JWT)<br/>(iss, aud, sub=user1, scopes)

    U->>A: Call agent with JWT<br/>Authorization: Bearer <user_jwt>

    Note over A,STS: Step 2: Agent exchanges token via STS

    A->>STS: Token Exchange Request (RFC 8693)<br/>• subject_token: user's JWT<br/>• actor_token: K8s ServiceAccount token<br/>• grant_type: urn:ietf:params:oauth:grant-type:token-exchange

    STS->>IdP: Validate subject token<br/>(JWKS verification)
    IdP-->>STS: Token valid ✓

    STS->>STS: Validate actor token<br/>(K8s token review)
    STS->>STS: Generate delegated token<br/>• Sub: user identity<br/>• Act: agent identity<br/>• Scopes: downscoped
    STS-->>A: Delegated Token (JWT)<br/>(includes both user + agent identity)

    Note over A,MCP: Step 3: Agent calls MCP with delegated token

    A->>AGW: MCP tool call<br/>Authorization: Bearer <delegated_token>

    AGW->>AGW: JWT validation<br/>(verify against STS issuer JWKS)

    AGW->>AGW: Policy evaluation:<br/>• Check user identity (sub)<br/>• Check agent identity (act)<br/>• Enforce RBAC / scopes

    AGW->>MCP: Forward tool call
    MCP-->>AGW: Tool result
    AGW-->>A: Tool result
    A-->>U: Final response

    Note over U,MCP: Audit log captures full chain:<br/>User → Agent → Tool
```

### Token Exchange Architecture

```
┌──────────────┐       ┌─────────────────────────────────────┐
│   AI Agent   │       │  Solo Enterprise for AgentGateway   │
│              │       │                                     │
│  Holds:      │       │  ┌───────────────────────────────┐  │
│  • User JWT  │──────►│  │  STS (Token Exchange Server)  │  │
│  • K8s SA    │       │  │  Port 7777                    │  │
│    token     │       │  │                               │  │
│              │       │  │  subjectValidator: remote     │  │
│  Does NOT    │       │  │    (OIDC JWKS URL)            │  │
│  hold:       │       │  │  actorValidator: k8s          │  │
│  • LLM keys  │       │  │    (ServiceAccount tokens)    │  │
│  • Tool creds│       │  │  tokenExpiration: 24h         │  │
│              │       │  └───────────────────────────────┘  │
│              │       │                                     │
│              │       │  ┌───────────────────────────────┐  │
│              │──────►│  │  Gateway Proxy                │  │
│              │       │  │  JWT Policy validates         │  │
│              │       │  │  delegated tokens from STS    │  │
│              │       │  └───────────────────────────────┘  │
└──────────────┘       └─────────────────────────────────────┘
```

---

## 11. Elicitations - Credential Gathering for Upstream APIs

> **Docs:** [About OBO and elicitations](https://docs.solo.io/agentgateway/2.1.x/security/obo-elicitations/about/) | [Elicitations](https://docs.solo.io/agentgateway/2.1.x/security/obo-elicitations/elicitations/)

Elicitations (MCP Protocol specification) enable AgentGateway to gather OAuth credentials from users when an upstream API requires tokens that are not yet available. Uses the Solo Enterprise UI for the OAuth authorization flow.

```mermaid
sequenceDiagram
    participant C as Client / Agent
    participant AGW as AgentGateway Proxy
    participant STS as AgentGateway STS<br/>(Token Exchange Server)
    participant UI as Solo Enterprise UI
    participant ExtIdP as External OAuth Provider<br/>(e.g., GitHub)
    participant API as Upstream API<br/>(e.g., GitHub API)

    Note over C,API: Step 1: Initial request — no upstream token available

    C->>AGW: Request to upstream API<br/>Authorization: Bearer <user_jwt>
    AGW->>STS: Request upstream token<br/>for this user + service
    STS->>STS: No stored token found
    STS-->>AGW: Elicitation URL (PENDING)<br/>status: PENDING
    AGW-->>C: Token exchange needed<br/>Elicitation URL provided

    Note over UI,ExtIdP: Step 2: User authorizes via Solo Enterprise UI

    UI->>UI: Admin opens Elicitations page<br/>Sees pending elicitation
    UI->>ExtIdP: Click "Authorize" →<br/>Redirect to OAuth provider
    ExtIdP->>ExtIdP: User logs in &<br/>grants consent
    ExtIdP-->>UI: Redirect back with<br/>authorization code
    UI->>STS: Complete elicitation<br/>(authorization code)
    STS->>ExtIdP: Exchange code for token
    ExtIdP-->>STS: Access Token for upstream API
    STS->>STS: Store token<br/>Elicitation → COMPLETED

    Note over C,API: Step 3: Retry request — token now available

    C->>AGW: Retry request to upstream API<br/>Authorization: Bearer <user_jwt>
    AGW->>STS: Request upstream token
    STS-->>AGW: Stored token found ✓
    AGW->>API: Forward request<br/>Authorization: Bearer <upstream_oauth_token><br/>(injected by AGW)
    API-->>AGW: Response
    AGW-->>C: 200 OK + Response

    Note over C,API: Upstream credentials never exposed<br/>to MCP servers or agents
```

### Elicitation Lifecycle

```mermaid
stateDiagram-v2
    [*] --> PENDING: Request needs upstream token<br/>Token not found in STS
    PENDING --> COMPLETED: User completes OAuth flow<br/>via Solo Enterprise UI
    PENDING --> FAILED: OAuth flow fails or<br/>times out
    COMPLETED --> [*]: Token available for injection<br/>into upstream requests
    FAILED --> PENDING: User retries authorization

    note right of PENDING
        Elicitation URL returned
        to caller. Admin opens
        URL in Solo Enterprise UI.
    end note

    note right of COMPLETED
        Token stored in STS.
        AgentGateway injects token
        into upstream requests.
    end note
```

---

## 12. Combined Security Architecture - End-to-End Deployment View

This diagram shows how all security layers work together in a typical enterprise deployment.

```mermaid
sequenceDiagram
    participant U as End User /<br/>AI Agent Client
    participant IdP as OIDC Identity Provider<br/>(Keycloak / Okta / Azure AD)
    participant AGW as AgentGateway Proxy<br/>(Rust-based)
    participant EA as Ext Auth Service<br/>(Solo Enterprise)
    participant STS as STS Token Exchange<br/>(Port 7777)
    participant Agent as AI Agent<br/>(K8s Pod)
    participant LLM as LLM Provider<br/>(OpenAI / Anthropic)
    participant MCP as MCP Tool Server<br/>(GitHub / DB / etc.)
    participant ExtAPI as External API<br/>(GitHub API, etc.)

    Note over U,ExtAPI: ── Layer 1: Browser Security (CORS + CSRF) ──

    rect rgb(255, 248, 230)
        U->>AGW: Preflight OPTIONS (if browser)
        AGW->>AGW: CORS: validate origin<br/>CSRF: validate origin vs destination
        AGW-->>U: CORS headers / 403 if blocked
    end

    Note over U,ExtAPI: ── Layer 2: Authentication ──

    rect rgb(230, 245, 255)
        U->>IdP: Authenticate (login / client_credentials)
        IdP-->>U: Access Token (JWT)

        U->>AGW: Request + Bearer JWT
        AGW->>AGW: JWT Auth (native):<br/>Verify signature via JWKS<br/>Check iss, aud, exp

        AGW->>AGW: Native Basic / API Key auth<br/>(if configured, no ext service)

        Note right of AGW: OR use Ext Auth Service<br/>for OAuth / BYO auth
        AGW->>EA: Ext Auth check (if configured)
        EA-->>AGW: Auth decision
    end

    Note over U,ExtAPI: ── Layer 3: Token Exchange (OBO) ──

    rect rgb(230, 255, 230)
        AGW->>Agent: Forward to AI Agent
        Agent->>STS: Exchange user JWT for<br/>delegated token (OBO)
        STS->>STS: Validate user token (JWKS)<br/>Validate agent (K8s SA)
        STS-->>Agent: Delegated token<br/>(user + agent identity)
    end

    Note over U,ExtAPI: ── Layer 4: Downstream Calls ──

    rect rgb(245, 230, 255)
        Agent->>AGW: LLM request (no auth needed)
        AGW->>AGW: PII redaction, prompt guard
        AGW->>LLM: Forward (AGW injects API key)
        LLM-->>AGW: Response
        AGW->>AGW: Credential leak check
        AGW-->>Agent: Sanitized response

        Agent->>AGW: MCP tool call + delegated JWT
        AGW->>AGW: Validate delegated token<br/>Check scopes / RBAC
        AGW->>MCP: Execute tool call
        MCP-->>AGW: Result
        AGW-->>Agent: Tool result
    end

    Note over U,ExtAPI: ── Layer 5: Elicitations (if needed) ──

    rect rgb(255, 240, 240)
        Agent->>AGW: Call upstream API
        AGW->>STS: Need upstream OAuth token
        STS-->>AGW: Elicitation URL (PENDING)
        Note over U: User completes OAuth flow<br/>via Solo Enterprise UI
        STS->>STS: Store upstream token (COMPLETED)
        Agent->>AGW: Retry upstream call
        AGW->>STS: Fetch stored token
        AGW->>ExtAPI: Inject upstream OAuth token
        ExtAPI-->>AGW: Response
        AGW-->>Agent: Response
    end

    Agent-->>U: Final response
```

---

## Quick Reference: Which Security Option to Use

| Scenario | Recommended Option |
|---|---|
| Browser-based web apps calling APIs | **CORS** + **CSRF** |
| Simple service-to-service auth | **API Key** (native) |
| Human users logging in (interactive) | **OAuth Authorization Code** |
| Programmatic API access with IdP | **OAuth Access Token** or **JWT** |
| High-performance token validation | **JWT (Native)** |
| Agent acting on behalf of user | **OBO Token Exchange** |
| Agent needs upstream API credentials | **Elicitations** |
| Custom auth logic / legacy systems | **BYO Ext Auth** |
| Internal testing / simple scenarios | **Basic Auth** (native) |
