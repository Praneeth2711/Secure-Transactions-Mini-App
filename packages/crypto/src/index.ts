import crypto from "crypto";

export const ALG = "aes-256-gcm";

const MASTER_KEY = crypto
  .createHash("sha256")
  .update(process.env.MASTER_KEY || "dev_master_key")
  .digest(); // 32 bytes

function ensureLength(buf: Buffer, expected: number, field: string) {
  if (buf.length !== expected) {
    throw new Error(`${field} must be ${expected} bytes`);
  }
}

function isHex(str: string) {
  return /^[0-9a-fA-F]+$/.test(str);
}

export function encryptEnvelope(payload: object) {
  const payloadBuffer = Buffer.from(JSON.stringify(payload));

  // Generate DEK (32 bytes)
  const dek = crypto.randomBytes(32);

  // Encrypt payload
  const payloadNonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALG, dek, payloadNonce);

  const payloadCt = Buffer.concat([
    cipher.update(payloadBuffer),
    cipher.final(),
  ]);

  const payloadTag = cipher.getAuthTag();

  // Wrap DEK
  const dekNonce = crypto.randomBytes(12);
  const wrapCipher = crypto.createCipheriv(ALG, MASTER_KEY, dekNonce);

  const dekWrapped = Buffer.concat([
    wrapCipher.update(dek),
    wrapCipher.final(),
  ]);

  const dekTag = wrapCipher.getAuthTag();

  return {
    payload_nonce: payloadNonce.toString("hex"),
    payload_ct: payloadCt.toString("hex"),
    payload_tag: payloadTag.toString("hex"),
    dek_wrap_nonce: dekNonce.toString("hex"),
    dek_wrapped: dekWrapped.toString("hex"),
    dek_wrap_tag: dekTag.toString("hex"),
  };
}

export function decryptEnvelope(record: any) {
  const {
    payload_nonce,
    payload_ct,
    payload_tag,
    dek_wrap_nonce,
    dek_wrapped,
    dek_wrap_tag,
  } = record;

  if (!isHex(payload_nonce) || !isHex(payload_tag) || !isHex(dek_wrap_nonce) || !isHex(dek_wrap_tag)) {
    throw new Error("Invalid hex input");
  }

  const payloadNonce = Buffer.from(payload_nonce, "hex");
  const payloadCt = Buffer.from(payload_ct, "hex");
  const payloadTag = Buffer.from(payload_tag, "hex");

  const dekNonce = Buffer.from(dek_wrap_nonce, "hex");
  const dekWrapped = Buffer.from(dek_wrapped, "hex");
  const dekTag = Buffer.from(dek_wrap_tag, "hex");

  ensureLength(payloadNonce, 12, "payload_nonce");
  ensureLength(payloadTag, 16, "payload_tag");
  ensureLength(dekNonce, 12, "dek_wrap_nonce");
  ensureLength(dekTag, 16, "dek_wrap_tag");

  // Unwrap DEK
  const unwrap = crypto.createDecipheriv(ALG, MASTER_KEY, dekNonce);
  unwrap.setAuthTag(dekTag);

  const dek = Buffer.concat([
    unwrap.update(dekWrapped),
    unwrap.final(),
  ]);

  // Decrypt payload
  const decipher = crypto.createDecipheriv(ALG, dek, payloadNonce);
  decipher.setAuthTag(payloadTag);

  const decrypted = Buffer.concat([
    decipher.update(payloadCt),
    decipher.final(),
  ]);

  return JSON.parse(decrypted.toString());
}
