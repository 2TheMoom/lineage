// Live helper for Lineage on Bradbury.
//   node scripts/live.mjs id <artifactUrl> <manifestUrl> <filename> [parentId]
//   node scripts/live.mjs attest <artifactUrl> <manifestUrl> <filename> [parentId]
//   node scripts/live.mjs check <attestationId>
//   node scripts/live.mjs show <attestationId>
//   node scripts/live.mjs trace <attestationId>
//   node scripts/live.mjs trusted <attestationId> [maxAgeSeconds]
//   node scripts/live.mjs lookup <sha256>
// Signs with a dedicated testnet wallet kept outside the repo.
import { readFileSync } from "fs";
import { createAccount, createClient } from "genlayer-js";
import { testnetBradbury } from "genlayer-js/chains";

const CONTRACT = process.env.LINEAGE || "";
if (!CONTRACT) {
  console.error("set LINEAGE=<contract address>");
  process.exit(1);
}
const WALLETS = JSON.parse(readFileSync("C:/Users/olumi/.genlayer-test-wallets/wallets.json", "utf8"));
const client = createClient({ chain: testnetBradbury, account: createAccount(WALLETS["gl-test-1"].privateKey) });

const j = (x) => JSON.stringify(x, (k, v) => (typeof v === "bigint" ? v.toString() : v), 1);
const plain = (x) => (x instanceof Map ? Object.fromEntries([...x].map(([k, v]) => [k, plain(v)])) : Array.isArray(x) ? x.map(plain) : x);

async function read(functionName, args) {
  for (let i = 0; i < 6; i++) {
    try {
      return plain(await client.readContract({ address: CONTRACT, functionName, args }));
    } catch (e) {
      if (i === 5) throw e;
      await new Promise((r) => setTimeout(r, 8000));
    }
  }
}

async function write(functionName, args) {
  let hash;
  for (let attempt = 1; ; attempt++) {
    try {
      hash = await client.writeContract({ address: CONTRACT, functionName, args });
      break;
    } catch (e) {
      if (attempt >= 5) throw e;
      console.log("  (send failed, retrying)");
      await new Promise((r) => setTimeout(r, 10000));
    }
  }
  console.log(`  ${functionName} tx ${hash}`);
  for (let attempt = 1; ; attempt++) {
    try {
      const r = await client.waitForTransactionReceipt({ hash, retries: 200 });
      console.log(`  exec=${r.txExecutionResultName} result=${r.resultName}`);
      return { hash, r };
    } catch (e) {
      if (attempt >= 10) throw e;
      console.log("  (receipt poll failed, retrying)");
      await new Promise((r) => setTimeout(r, 15000));
    }
  }
}

const [cmd, ...a] = process.argv.slice(2);
if (cmd === "id") {
  console.log(await read("attestation_id", [a[0], a[1], a[2], a[3] || ""]));
} else if (cmd === "attest") {
  const id = await read("attestation_id", [a[0], a[1], a[2], a[3] || ""]);
  await write("attest", [a[0], a[1], a[2], a[3] || ""]);
  console.log("id:", id);
} else if (cmd === "check") {
  await write("check", [a[0]]);
  await new Promise((r) => setTimeout(r, 15000)); // let the new state propagate before reading
  console.log(j(await read("get_attestation", [a[0]])));
} else if (cmd === "show") {
  console.log(j(await read("get_attestation", [a[0]])));
} else if (cmd === "trace") {
  console.log(j(await read("trace", [a[0]])));
} else if (cmd === "trusted") {
  console.log("is_trusted:", await read("is_trusted", [a[0], Number(a[1] || 0)]));
} else if (cmd === "lookup") {
  console.log(j(await read("lookup", [a[0]])));
} else {
  console.error("unknown command");
  process.exit(1);
}
