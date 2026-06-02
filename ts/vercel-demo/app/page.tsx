export default function Home() {
  return (
    <main style={{ fontFamily: "system-ui, sans-serif", maxWidth: 640, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>pops gating demo</h1>
      <p>
        <code>GET /api/secret</code> is gated by Proof-of-Payment. A bare request returns{" "}
        <strong>402</strong> with a <code>WWW-Authenticate: Payment</code> challenge. Presenting a
        valid <code>cashuB</code> token in <code>Authorization: Payment</code> runs the full
        verify + NUT-03 swap (compiled to WASM, executed in a Node serverless function over an
        injected <code>fetch</code>) and returns <strong>200</strong> with the gated payload.
      </p>
      <p>
        Try it: <code>curl -i /api/secret</code> for the 402, then retry with a credential.
      </p>
    </main>
  );
}
