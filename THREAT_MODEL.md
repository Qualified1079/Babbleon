# Babbleon Threat Model

## Primary Threat: LLM Worms

The main threat model for Babbleon is **LLM worms** — self-propagating
prompt-injection payloads that spread between LLM-integrated agents and
applications by embedding adversarial instructions in content that other
agents will later ingest (emails, documents, RAG corpora, tool outputs,
shared memory).

### Definition

An LLM worm is a self-propagating attack that spreads through networks of
LLM-integrated agents by embedding an **adversarial self-replicating
prompt** inside content the models ingest. The canonical demonstration is
**Morris II**, introduced in Cohen, Bitton, and Nassi's 2024 paper
*ComPromptMized: Unleashing Zero-click Worms that Target GenAI-Powered
Applications*. Such a prompt couples two functions:

- A **replication payload** that induces the receiving model to reproduce
  the malicious prompt in its own output.
- A **malicious payload** (exfiltration, spam, tool misuse, etc.).

Because propagation rides on natural-language content the model itself
generates and forwards, no user click is required — this is a "zero-click"
class of attack.

### Propagation Mechanisms

Worms ride on **indirect prompt injection** (Greshake et al., 2023):
instructions hidden inside data the LLM later processes as context. In a
connected GenAI ecosystem — email assistants, RAG retrievers, agentic tool
users — an infected artifact is ingested by one agent, whose outputs (a
reply, a new document, an updated vector-store entry) carry the replicated
prompt to the next agent that touches them. RAG stores are a particularly
fertile substrate: poisoned entries persist and are re-served to many
downstream agents.

### In-Scope Propagation Paths for Babbleon

*(To be filled in as the system takes shape — enumerate every surface
where third-party or user-supplied text can reach a model, and every
outbound surface where model output can reach another agent or a shared
store.)*

### Mitigations

- **Isolate untrusted content**: treat all retrieved / third-party text as
  data, not instructions (spotlighting, delimiter tagging, dual-LLM
  patterns).
- **Provenance and taint tracking**: label content by trust level; refuse
  to let low-trust text drive high-privilege tool calls.
- **Least-privilege tool scopes**: minimize each agent's outbound actions
  (send-email, write-to-store) and gate cross-agent writes.
- **Input/output filtering**: injection-pattern classifiers on inputs;
  scan generated outputs before they are stored, sent, or re-ingested —
  breaking the replication loop is the single most valuable choke point.
- **Human-in-the-loop** confirmation for outbound or irreversible actions.
- **RAG hygiene**: signed / curated corpora, write-path review, anomaly
  detection on new entries.
- **Rate limiting and egress monitoring** to contain propagation velocity.

Aligns with **OWASP LLM01:2025 (Prompt Injection)** layered-defense
guidance.

### Out of Scope

*(To be filled in.)*

### References

- Cohen, Bitton, Nassi (2024), *ComPromptMized* — https://github.com/Havenbreaker/CPM
- Greshake et al. (2023), *Indirect Prompt Injection*
- *Open Challenges in Multi-Agent Security* — https://arxiv.org/pdf/2505.02077
- *LLM in the Middle: Systematic Review* — https://arxiv.org/pdf/2509.10682
- OWASP LLM01:2025 — https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- Microsoft MSRC, *Defending against indirect prompt injection* (2025) —
  https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks
- Lakera, *Indirect Prompt Injection* — https://www.lakera.ai/blog/indirect-prompt-injection
