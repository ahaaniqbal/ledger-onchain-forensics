# Quorum — Loom / demo video script (~2.5 min)

**Setup before recording:** dashboard running at `localhost:8000`, on the **Monitor**
tab. Landing page open in a second tab (optional cold-open). Strip the agentation
toolbar first (it's dev-only). Speak calm and confident — let the visuals breathe.

---

### 0:00 — Cold open (Landing → app) [~12s]
> "Crypto lost seventeen billion dollars to scams last year. Finding a single rug
> takes a compliance analyst hours. So we built **Quorum** — an autonomous agent
> that finds the scams on its own."

*(Click "Launch dashboard →". Land on Monitor.)*

### 0:12 — Monitor: it's already working [~25s]
> "This isn't a search box. Quorum is **already** scoring sixty-five thousand tokens
> across twenty-five million real Ethereum transactions — through Emergence CRAFT.
> Every red row is a token it already doesn't trust. It's on duty."

*(Gesture at the stat tiles + the autonomous threat feed.)*

### 0:37 — Dispatch the agent [~30s]
> "I don't hand it a wallet — it picks the worst threat itself."

*(Click **⚡ Dispatch agent → #1 threat**. It jumps to Investigate and starts streaming.)*

> "Watch it think. It orients itself in CRAFT's semantic layer, then writes its own
> SQL — holder concentration, deployer dominance, a lifecycle that spikes and dies in
> a day."

*(Point at the lifecycle chart: the pump-then-collapse curve with the red 'rug' marker.)*

> "There's the shape of the rug — and it flags exactly where the fraud fires."

### 1:07 — The verdict + the pivot [~20s]
*(Verdict gauge locks.)*
> "Verdict: **likely rug, ninety-nine out of a hundred.** But here's what I never
> hard-coded — on its own, it pivots: *if this is a rug, is it the only one?* — and
> fingerprints the bytecode."

### 1:27 — Campaigns: unmask the operator [~30s]
*(Click **Campaigns**. Click the top operator row — the Resolve sweep fires.)*
> "It clustered **all** sixty-five thousand tokens by bytecode and resolved the
> operators behind them. This one fingerprint? **A hundred and seventy-two rug tokens.
> Thirteen thousand victims.** One operator, a whole fleet — as a link chart."

> "Across the chain: fifteen rug-kit operators, twenty-four thousand victims. That's
> not 'this token looks bad.' That's the whole operation."

### 1:57 — Protect: block it everywhere [~20s]
*(Click **Protect · API**. Click "Query risk API".)*
> "And this is how it scales. A wallet, an exchange, a protocol calls this API before
> every transaction. Response: **block.** One integration protects every user, on
> every token — automatically."

### 2:17 — Enterprise close [~15s]
> "Quorum is an autonomous compliance analyst for Web3 — the on-chain half of an
> investigation, in minutes instead of hours, over real enterprise data through CRAFT.
> Nebius reasons, CRAFT queries, Quorum decides."

> "Twenty-five million transactions. One word. **Block.**"

---

**Backup line if a live run is slow:** "These investigations take about a minute of
real multi-step reasoning — here's one it already completed" *(switch to a cached run)*.
