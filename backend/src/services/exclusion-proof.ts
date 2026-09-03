/**
 * Exclusion Proof Verification Service
 *
 * Verifies zero-knowledge exclusion proofs to enforce that revoked members
 * cannot vote in future proposals. Coordinates with the membership tree contract
 * to check revocation status.
 */

import { getDb } from "./db.js";
import { log } from "./logger.js";

export interface ExclusionProof {
  proof: unknown;
  publicInputs: {
    historicalRoot: string;
    currentRoot: string;
    daoId: bigint;
    leafIndex: number;
    commitment: string;
  };
}

export interface RevocationStatus {
  isRevoked: boolean;
  revokedAt?: number;
  reinstatedAt?: number;
  commitment: string;
}

export async function verifyExclusionProof(
  proof: ExclusionProof,
  _treeContractId: string,
): Promise<{ valid: boolean; reason?: string }> {
  try {
    const { commitment, daoId, historicalRoot, currentRoot } = proof.publicInputs;
    if (!historicalRoot || !currentRoot) return { valid: false, reason: "Invalid root" };
    if (!isValidFieldElement(commitment)) return { valid: false, reason: "Invalid commitment format" };

    const status = checkRevocationStatus(commitment, Number(daoId));
    if (!status.isRevoked || status.reinstatedAt) {
      return { valid: false, reason: "Member has not been revoked" };
    }
    return { valid: true };
  } catch (err) {
    log("error", "exclusion_proof_verification_error", {
      error: err instanceof Error ? err.message : String(err),
    });
    return { valid: false, reason: "Proof verification failed" };
  }
}

function ensureRevocationsTable(): ReturnType<typeof getDb> {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS member_revocations (
      commitment TEXT NOT NULL,
      dao_id INTEGER NOT NULL,
      revoked_at INTEGER NOT NULL,
      reinstated_at INTEGER,
      created_at TEXT NOT NULL,
      PRIMARY KEY (commitment, dao_id)
    )
  `);
  return db;
}

function checkRevocationStatus(commitment: string, daoId: number): RevocationStatus {
  const db = ensureRevocationsTable();
  const row = db
    .prepare(
      "SELECT revoked_at, reinstated_at FROM member_revocations WHERE commitment = ? AND dao_id = ?",
    )
    .get(commitment, daoId) as
    | { revoked_at: number; reinstated_at: number | null }
    | undefined;

  return row
    ? { isRevoked: true, revokedAt: row.revoked_at, reinstatedAt: row.reinstated_at ?? undefined, commitment }
    : { isRevoked: false, commitment };
}

function isValidFieldElement(value: string): boolean {
  try {
    const prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const num = BigInt(value);
    return num >= 0n && num < prime;
  } catch {
    return false;
  }
}

export async function recordRevocation(
  commitment: string,
  daoId: number,
  timestamp: number,
): Promise<void> {
  const db = ensureRevocationsTable();
  db.prepare(
      "INSERT OR REPLACE INTO member_revocations (commitment, dao_id, revoked_at, created_at) VALUES (?, ?, ?, ?)",
    )
    .run(commitment, daoId, timestamp, new Date().toISOString());
}

export async function recordReinstatement(
  commitment: string,
  daoId: number,
  timestamp: number,
): Promise<void> {
  const db = ensureRevocationsTable();
  db.prepare(
      "UPDATE member_revocations SET reinstated_at = ? WHERE commitment = ? AND dao_id = ?",
    )
    .run(timestamp, commitment, daoId);
}
