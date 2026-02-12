import Fastify from "fastify";
import cors from "@fastify/cors";
import { encryptEnvelope, decryptEnvelope } from "./crypto";
import crypto from "crypto";

const app = Fastify({ logger: true });

app.register(cors, {
  origin: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
});


type TxSecureRecord = {
  id: string;
  partyId: string;
  createdAt: string;
  payload_nonce: string;
  payload_ct: string;
  payload_tag: string;
  dek_wrap_nonce: string;
  dek_wrapped: string;
  dek_wrap_tag: string;
  alg: "AES-256-GCM";
  mk_version: 1;
};

const db = new Map<string, TxSecureRecord>();

app.post("/tx/encrypt", async (req, reply) => {
  const { partyId, payload } = req.body as any;

  if (!partyId || !payload) {
    return reply.status(400).send({ error: "Missing partyId or payload" });
  }

  const id = crypto.randomUUID();
  const encrypted = encryptEnvelope(payload);

  const record: TxSecureRecord = {
    id,
    partyId,
    createdAt: new Date().toISOString(),
    ...encrypted,
    alg: "AES-256-GCM",
    mk_version: 1,
  };

  db.set(id, record);
  return record;
});

app.post("/tx/:id/decrypt", async (req, reply) => {
  const { id } = req.params as any;
  const record = db.get(id);

  if (!record) {
    return reply.status(404).send({ error: "Not found" });
  }

  try {
    const decrypted = decryptEnvelope(record);
    return { payload: decrypted };
  } catch {
    return reply.status(400).send({ error: "Decryption failed" });
  }
});

/* -------------------------
   LOCAL DEVELOPMENT SERVER
-------------------------- */
if (process.env.NODE_ENV !== "production") {
  app.listen({ port: 3001 }, (err, address) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    console.log(`API running at ${address}`);
  });
}

/* -------------------------
   VERCEL SERVERLESS EXPORT
-------------------------- */
export default async function handler(req: any, res: any) {
  await app.ready();
  app.server.emit("request", req, res);
}
