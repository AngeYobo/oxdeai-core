import { readFileSync } from "node:fs";
import { verifyEnvelope } from "@oxdeai/core";

const path = process.argv[2];
if (!path) {
  console.error("usage: node verify-envelope.js <envelope.bin>");
  process.exit(1);
}

const envelopeBytes = new Uint8Array(readFileSync(path));
const result = verifyEnvelope(envelopeBytes);
console.log(JSON.stringify(result, null, 2));
