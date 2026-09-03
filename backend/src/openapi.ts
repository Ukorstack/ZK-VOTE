/**
 * OpenAPI 3.1 Specification Builder
 *
 * Builds the API's OpenAPI document from the same Zod schemas used to
 * validate requests at runtime (validation/schemas.ts and a couple of
 * route-local schemas), plus a compact per-endpoint metadata table below.
 * That table is also the source `scripts/generate-openapi.ts` uses to check
 * API.md doesn't drift from the implemented routes — see that script for how
 * the two stay in sync.
 */

import { z } from "zod";

export const daosListResponseSchema = z.object({
  data: z.array(z.object({ id: z.number() }).passthrough()),
  pagination: z.object({ total: z.number(), hasMore: z.boolean(), cursor: z.string().optional() }),
  lastSync: z.unknown().optional(),
  cached: z.boolean(),
});

export const openApiSpec = {
  openapi: "3.0.3",
  info: {
    title: "ZKVote Relayer API",
    version: "1.0.0",
    description: "Anonymous voting relayer with full audit trail and incident response",
  },
  servers: [{ url: "http://localhost:3001", description: "Local" }],
  security: [{ bearerAuth: [] }],
  components: {
    securitySchemes: {
      bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
      relayerAuth: { type: "apiKey", in: "header", name: "X-Relayer-Auth" },
    },
    schemas: {
      VoteRequest: {
        type: "object",
        required: ["daoId", "proposalId", "choice", "nullifier", "root", "proof"],
        properties: {
          daoId: { type: "integer" },
          proposalId: { type: "integer" },
          choice: { type: "boolean" },
          nullifier: { type: "string", description: "BN254 field element hex < modulus (redacted in audit)" },
          root: { type: "string", description: "Merkle root hex (redacted in audit)" },
          proof: { type: "object", description: "Groth16 proof (redacted in audit)", properties: { a: { type: "string" }, b: { type: "string" }, c: { type: "string" } } },
        },
      },
      AuditEntry: {
        type: "object",
        properties: {
          id: { type: "string" },
          timestamp: { type: "string", format: "date-time" },
          requestId: { type: "string" },
          method: { type: "string" },
          path: { type: "string" },
          action: { type: "string" },
          actor: { type: "string", description: "Hashed actor identifier (PII redacted)" },
          statusCode: { type: "integer" },
          immutable: { type: "boolean", enum: [true] },
        },
      },
      RemediationAction: {
        type: "object",
        required: ["action", "target", "reason", "idempotencyKey"],
        properties: {
          action: { type: "string", enum: ["freeze_dao", "unfreeze_dao", "pause_voting", "resume_voting", "revoke_member", "restore_member", "emergency_pause", "emergency_resume", "rotate_vk", "quarantine_proposal"] },
          target: { type: "string", description: "DAO or proposal identifier" },
          reason: { type: "string", minLength: 5 },
          idempotencyKey: { type: "string", minLength: 8, description: "Replay protection - duplicate keys return 409" },
          metadata: { type: "object", additionalProperties: true },
        },
      },
    },
    responseSchema: healthResponseSchema,
  },
  {
    method: "get",
    path: "/ready",
    tag: "Health",
    summary: "Readiness check (verifies RPC connectivity)",
    auth: false,
    rateLimit: null,
    responseExample: { status: "ready" },
    responseSchema: readyResponseSchema,
    errorStatuses: [503],
  },
  {
    method: "get",
    path: "/config",
    tag: "Health",
    summary: "Public configuration for frontend clients",
    auth: false,
    rateLimit: null,
    responseExample: {
      votingContract: "C...",
      networkPassphrase: "Test SDF Network ; September 2015",
      ipfsEnabled: true,
    },
    responseSchema: configResponseSchema,
  },
  {
    method: "get",
    path: "/db/stats",
    tag: "Health",
    summary: "Database diagnostics (full detail requires auth)",
    auth: true,
    rateLimit: null,
    responseExample: { queries: {}, tables: [], cache: {} },
  },
  // ---- Voting ----
  {
    method: "post",
    path: "/vote",
    tag: "Voting",
    summary: "Submit an anonymous vote with a ZK proof",
    auth: true,
    rateLimit: "voteLimiter",
    body: voteSchema,
    responseExample: {
      success: true,
      txHash: "a1b2c3...64hex",
      status: "SUCCESS",
    },
    responseSchema: successResponseSchema,
    errorStatuses: [400, 401, 429, 500, 503, 504],
  },
  {
    method: "get",
    path: "/proposal/:daoId/:proposalId",
    tag: "Voting",
    summary: "Get proposal vote tallies",
    auth: false,
    rateLimit: "queryLimiter",
    params: {
      daoId: idParam("0", "DAO identifier"),
      proposalId: idParam("1", "Proposal identifier"),
    },
    responseExample: { daoId: 0, proposalId: 1, yesVotes: 12, noVotes: 3 },
  },
  {
    method: "get",
    path: "/root/:daoId",
    tag: "Voting",
    summary: "Get the current membership merkle root for a DAO",
    auth: false,
    rateLimit: "queryLimiter",
    params: { daoId: idParam("0", "DAO identifier") },
    responseExample: { daoId: 0, root: "0x..." },
  },
  // ---- Comments ----
  {
    method: "post",
    path: "/comment/anonymous",
    tag: "Comments",
    summary: "Submit an anonymous comment with a ZK proof",
    auth: true,
    rateLimit: "commentLimiter",
    body: anonymousCommentSchema,
    responseExample: { success: true, commentId: 42, txHash: "a1b2c3...64hex" },
    responseSchema: successResponseSchema,
    errorStatuses: [400, 401, 429, 500, 503, 504],
  },
  {
    method: "get",
    path: "/comment/challenge/:commitment",
    tag: "Comments",
    summary: "Get a proof-of-work challenge for a commitment (anti-spam)",
    auth: false,
    rateLimit: "queryLimiter",
    params: { commitment: idParam("0x1234...64hex", "Commitment hash") },
    responseExample: {
      serverId: "abc123",
      difficulty: 20,
      expiresAt: 1785200000000,
    },
  },
  {
    method: "get",
    path: "/comments/:daoId/:proposalId/nonce",
    tag: "Comments",
    summary: "Get the next comment nonce for a commitment",
    auth: false,
    rateLimit: "queryLimiter",
    params: {
      daoId: idParam("0", "DAO identifier"),
      proposalId: idParam("1", "Proposal identifier"),
    },
    responseExample: { nonce: 0 },
  },
  {
    method: "get",
    path: "/comments/:daoId/:proposalId",
    tag: "Comments",
    summary: "List comments for a proposal (paginated)",
    auth: false,
    rateLimit: "queryLimiter",
    params: {
      daoId: idParam("0", "DAO identifier"),
      proposalId: idParam("1", "Proposal identifier"),
    },
    query: {
      limit: z
        .number()
        .int()
        .min(1)
        .max(500)
        .optional()
        .openapi({ example: 100 }),
      cursor: z.string().optional().openapi({ example: "eyJpIjoxMjN9" }),
    },
    responseExample: {
      data: [],
      pagination: { cursor: undefined, hasMore: false, total: 0 },
    },
    responseSchema: paginatedResponseSchema,
  },
  {
    method: "get",
    path: "/comment/:daoId/:proposalId/:commentId",
    tag: "Comments",
    summary: "Get a single comment",
    auth: false,
    rateLimit: "queryLimiter",
    params: {
      daoId: idParam("0", "DAO identifier"),
      proposalId: idParam("1", "Proposal identifier"),
      commentId: idParam("42", "Comment identifier"),
    },
    responseExample: {
      id: 42,
      daoId: 0,
      proposalId: 1,
      contentCid: "bafy...",
      isAnonymous: true,
    },
    errorStatuses: [404],
  },
  {
    method: "post",
    path: "/comment/edit",
    tag: "Comments",
    summary: "Edit a public (non-anonymous) comment",
    auth: true,
    rateLimit: "commentLimiter",
    body: editCommentSchema,
    responseExample: { success: true, txHash: "a1b2c3...64hex" },
    responseSchema: successResponseSchema,
    errorStatuses: [400, 401, 403, 500, 503],
  },
  {
    method: "post",
    path: "/comment/delete",
    tag: "Comments",
    summary: "Delete a public (non-anonymous) comment",
    auth: true,
    rateLimit: "commentLimiter",
    body: deleteCommentSchema,
    responseExample: { success: true, txHash: "a1b2c3...64hex" },
    responseSchema: successResponseSchema,
    errorStatuses: [400, 401, 403, 500, 503],
  },
  {
    method: "post",
    path: "/comment/flag",
    tag: "Comments",
    summary: "Flag a comment as spam (anti-spam, auto-hide at threshold)",
    auth: true,
    rateLimit: "commentLimiter",
    body: flagCommentSchema,
    responseExample: {
      success: true,
      hidden: false,
      flagCount: 1,
      threshold: 3,
    },
    errorStatuses: [400, 401, 500],
  },
  // ---- DAOs ----
  {
    method: "get",
    path: "/daos",
    tag: "DAOs",
    summary:
      "List cached DAOs with pagination, optionally including user membership role",
    auth: false,
    rateLimit: "queryLimiter",
    query: {
      user: z
        .string()
        .optional()
        .openapi({ example: "GABCDEF...", description: "Stellar address" }),
      limit: z
        .number()
        .int()
        .min(1)
        .max(500)
        .optional()
        .openapi({ example: 100, description: "Page size (default 100)" }),
      offset: z
        .number()
        .int()
        .min(0)
        .optional()
        .openapi({ example: 0, description: "Rows to skip (default 0)" }),
      cursor: z.string().optional().openapi({
        example: "100",
        description:
          "Opaque cursor from a previous pagination.cursor; alias for offset",
      }),
    },
    responseExample: {
      data: [],
      pagination: { cursor: undefined, hasMore: false, total: 0 },
      lastSync: null,
      cached: true,
    },
    responseSchema: daosListResponseSchema,
    errorStatuses: [400, 500],
  },
  {
    method: "get",
    path: "/dao/:daoId",
    tag: "DAOs",
    summary: "Get a single cached DAO",
    auth: false,
    rateLimit: "queryLimiter",
    params: { daoId: idParam("0", "DAO identifier") },
    responseExample: {
      dao: { id: 0, name: "Example DAO", creator: "GABCDEF..." },
      cached: true,
    },
    errorStatuses: [404],
  },
  {
    method: "post",
    path: "/daos/sync",
    tag: "DAOs",
    summary: "Trigger a manual DAO sync from the on-chain registry",
    auth: true,
    rateLimit: null,
    responseExample: { success: true, synced: 5 },
    errorStatuses: [401, 500],
  },
  // ---- IPFS ----
  {
    method: "get",
    path: "/ipfs/health",
    tag: "IPFS",
    summary: "IPFS pinning service health",
    auth: false,
    rateLimit: "queryLimiter",
    responseExample: { enabled: true, ok: true },
  },
  {
    method: "post",
    path: "/ipfs/image",
    tag: "IPFS",
    summary: 'Upload an image to IPFS (multipart/form-data, field "image")',
    auth: true,
    rateLimit: "ipfsUploadLimiter",
    responseExample: {
      cid: "bafybei...",
      size: 10240,
      filename: "photo.png",
      mimeType: "image/png",
    },
    errorStatuses: [400, 401, 429, 500, 503],
  },
  {
    method: "post",
    path: "/ipfs/metadata",
    tag: "IPFS",
    summary: "Upload proposal/comment metadata JSON to IPFS",
    auth: true,
    rateLimit: "ipfsUploadLimiter",
    responseExample: { cid: "bafybei...", size: 512 },
    errorStatuses: [400, 401, 429, 500, 503],
  },
  {
    method: "get",
    path: "/ipfs/:cid",
    tag: "IPFS",
    summary: "Retrieve JSON content pinned to IPFS",
    auth: false,
    rateLimit: "ipfsReadLimiter",
    params: { cid: idParam("bafybei...", "IPFS CID") },
    responseExample: { version: 1, body: "..." },
    errorStatuses: [404],
  },
  {
    method: "get",
    path: "/ipfs/image/:cid",
    tag: "IPFS",
    summary: "Retrieve an image pinned to IPFS",
    auth: false,
    rateLimit: "ipfsReadLimiter",
    params: { cid: idParam("bafybei...", "IPFS CID") },
    responseExample: "(binary image data)",
    errorStatuses: [404],
  },
  // ---- Events ----
  {
    method: "get",
    path: "/events/archived",
    tag: "Events",
    summary: "List historical event archives",
    auth: false,
    rateLimit: "queryLimiter",
    query: { daoId: z.string().optional().openapi({ example: "0" }) },
    responseExample: { archives: [], total: 0 },
  },
  {
    method: "get",
    path: "/events/archived/:archiveId",
    tag: "Events",
    summary: "Retrieve historical archived events",
    auth: false,
    rateLimit: "queryLimiter",
    params: {
      archiveId: idParam("archive_dao_0_1785200000000", "Archive identifier"),
    },
    responseExample: {
      archiveId: "archive_dao_0_1785200000000",
      events: [],
      total: 0,
    },
  },
  {
    method: "get",
    path: "/events/:daoId",
    tag: "Events",
    summary: "Get events for a DAO with cursor-based pagination",
    auth: false,
    rateLimit: "queryLimiter",
    params: { daoId: idParam("0", "DAO identifier") },
    query: {
      limit: z
        .number()
        .int()
        .min(1)
        .max(500)
        .optional()
        .openapi({ example: 100 }),
      cursor: z.string().optional().openapi({ example: "eyJpIjoxMjN9" }),
      types: z
        .string()
        .optional()
        .openapi({ example: "vote_cast,proposal_created" }),
      orderBy: z
        .enum(["id", "timestamp", "ledger", "type", "verified", "created_at"])
        .optional()
        .openapi({ example: "timestamp" }),
      orderDirection: z
        .enum(["ASC", "DESC"])
        .optional()
        .openapi({ example: "DESC" }),
      cursorField: z
        .enum(["id", "ledger", "timestamp"])
        .optional()
        .openapi({ example: "id" }),
    },
    responseExample: {
      data: [],
      pagination: { cursor: undefined, hasMore: false, total: 0 },
    },
    responseSchema: paginatedResponseSchema,
  },
  {
    method: "get",
    path: "/indexer/status",
    tag: "Events",
    summary: "Event indexer status",
    auth: false,
    rateLimit: "queryLimiter",
    responseExample: { running: true, lastLedger: 0 },
  },
  {
    method: "get",
    path: "/indexer/daos",
    tag: "Events",
    summary: "List all indexed DAOs with event counts",
    auth: false,
    rateLimit: "queryLimiter",
    responseExample: { daos: [] },
  },
  {
    method: "post",
    path: "/events",
    tag: "Events",
    summary: "Manually insert an event (admin only)",
    auth: true,
    rateLimit: null,
    body: manualEventSchema,
    responseExample: { success: true },
    errorStatuses: [400, 401, 500],
  },
  {
    method: "post",
    path: "/events/notify",
    tag: "Events",
    summary: "Frontend notification of an unverified on-chain event",
    auth: true,
    rateLimit: "queryLimiter",
    body: notifyEventSchema,
    responseExample: {
      success: true,
      message: "Event queued for verification",
    },
    errorStatuses: [400, 401, 429, 500],
  },
  // ---- Bridge ----
  {
    method: "post",
    path: "/bridge/vote",
    tag: "Bridge",
    summary: "Submit a cross-chain (EVM -> Soroban) vote",
    auth: false,
    rateLimit: null,
    body: bridgeVoteSchema,
    responseExample: { success: true, txHash: "a1b2c3...64hex" },
    responseSchema: successResponseSchema,
    errorStatuses: [400, 500],
  },
  {
    method: "get",
    path: "/bridge/nullifier/:daoId/:proposalId/:nullifier",
    tag: "Bridge",
    summary: "Check whether a nullifier has already been used",
    auth: false,
    rateLimit: "queryLimiter",
    params: {
      daoId: idParam("0", "DAO identifier"),
      proposalId: idParam("1", "Proposal identifier"),
      nullifier: idParam("0x1234...", "Nullifier hash"),
    },
    responseExample: {
      daoId: 0,
      proposalId: 1,
      nullifier: "0x1234...",
      used: false,
    },
    errorStatuses: [404, 500],
  },
  {
    method: "post",
    path: "/bridge/relay",
    tag: "Bridge",
    summary: "Manually trigger cross-chain event relay (admin only)",
    auth: true,
    rateLimit: null,
    responseExample: { success: true },
    errorStatuses: [401, 500],
  },
  // ---- Circuits ----
  {
    method: "get",
    path: "/circuits/:dao/:type/status",
    tag: "Circuits",
    summary: "Get the active/available ZK circuit versions for a DAO",
    auth: false,
    rateLimit: "queryLimiter",
    params: circuitParamsSchema.shape,
    responseExample: {
      daoId: 0,
      circuitType: "Vote",
      currentCircuit: "vote_v1",
      availableCircuits: [],
    },
  },
  // ---- Admin ----
  {
    method: "get",
    path: "/admin/audit-log",
    tag: "Admin",
    summary: "Paginated, hash-chain-verifiable audit log review (admin only)",
    auth: true,
    rateLimit: "queryLimiter",
    query: {
      limit: z.string().optional().openapi({ example: "50" }),
      offset: z.string().optional().openapi({ example: "0" }),
      action: z.string().optional().openapi({ example: "vote_relay" }),
      format: z.enum(["json", "cef"]).optional(),
      verify: z.enum(["true", "false"]).optional(),
    },
    responseExample: { logs: [], total: 0, limit: 50, offset: 0 },
    errorStatuses: [401, 500],
  },
  {
    method: "get",
    path: "/admin/sbt-transfer-attempts",
    tag: "Admin",
    summary:
      "Review flagged membership-SBT transfer/approval attempts for a DAO (admin only)",
    auth: true,
    rateLimit: "queryLimiter",
    query: {
      daoId: z.string().openapi({ example: "1" }),
      limit: z.string().optional().openapi({ example: "50" }),
      offset: z.string().optional().openapi({ example: "0" }),
    },
    responseExample: { daoId: 1, attempts: [], total: 0, limit: 50, offset: 0 },
    errorStatuses: [400, 401, 500],
  },
  // ---- Membership ----
  {
    method: "post",
    path: "/membership/register-commitment",
    tag: "Membership",
    summary:
      "Prepare a commitment registration transaction (per-member rate limited, #371)",
    auth: true,
    rateLimit: "commitmentRegistrationLimiter",
    body: membershipRegisterSchema,
    responseExample: {
      success: true,
      prepared: true,
      daoId: 0,
      caller: "G...",
      transactionXdr: "AAAA...",
      authEntry: ["AAAAA..."],
    },
    errorStatuses: [400, 401, 403, 409, 429, 500, 503, 504],
  },
  // ---- Audit ----
  {
    method: "get",
    path: "/audit/logs",
    tag: "Audit",
    summary: "Query audit logs (redacted, authz)",
    auth: true,
    rateLimit: "queryLimiter",
    query: {
      action: z.string().optional().openapi({ example: "vote_relay" }),
      actor: z.string().optional().openapi({ example: "member_123" }),
      method: z.string().optional().openapi({ example: "POST" }),
      path: z.string().optional().openapi({ example: "/vote" }),
      from: z.string().optional().openapi({ example: "2026-01-01T00:00:00Z" }),
      to: z.string().optional().openapi({ example: "2026-12-31T23:59:59Z" }),
      limit: z.string().optional().openapi({ example: "50" }),
      offset: z.string().optional().openapi({ example: "0" }),
    },
    responseExample: { entries: [], total: 0, limit: 50, offset: 0 },
    errorStatuses: [400, 401, 500],
  },
  {
    method: "get",
    path: "/audit/export",
    tag: "Audit",
    summary: "Export audit logs (json/csv)",
    auth: true,
    rateLimit: "queryLimiter",
    query: {
      format: z.enum(["json", "csv"]).optional().openapi({ example: "json" }),
    },
    responseExample: "[]",
    errorStatuses: [400, 401, 500],
  },
  {
    method: "get",
    path: "/audit/stats",
    tag: "Audit",
    summary: "Audit statistics",
    auth: true,
    rateLimit: "queryLimiter",
    responseExample: {
      total: 0,
      byAction: {},
      byMethod: {},
      oldest: null,
      newest: null,
    },
    errorStatuses: [401, 500],
  },
];

// ============================================
// SPEC BUILDER
// ============================================

const SECURITY_SCHEME = "RelayerAuth";

function toOpenApiPath(expressPath: string): string {
  return expressPath.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, "{$1}");
}

export function buildOpenApiDocument() {
  const registry = new OpenAPIRegistry();

  registry.registerComponent("securitySchemes", SECURITY_SCHEME, {
    type: "apiKey",
    in: "header",
    name: "X-Relayer-Auth",
    description:
      "Shared relayer auth token (also accepted as `Authorization: Bearer <token>`). " +
      "There is currently one shared token per deployment, not per-user credentials.",
  });

  for (const ep of ENDPOINTS) {
    const responses: Record<string, ResponseConfig> = {
      200: {
        description: "Success",
        content: {
          "application/json": {
            schema: ep.responseSchema ?? z.any(),
            example: ep.responseExample,
          },
        },
      },
    };

    for (const status of ep.errorStatuses ?? []) {
      responses[status] = {
        description: `Error (HTTP ${status})`,
        content: { "application/json": { schema: errorResponseSchema } },
      };
    }

    registry.registerPath({
      method: ep.method,
      path: toOpenApiPath(ep.path),
      tags: [ep.tag],
      summary: ep.summary,
      description: ep.rateLimit
        ? `Rate limit: ${ep.rateLimit}.`
        : "No rate limit.",
      security: ep.auth ? [{ [SECURITY_SCHEME]: [] }] : [],
      request: {
        ...(ep.params ? { params: z.object(ep.params) } : {}),
        ...(ep.query ? { query: z.object(ep.query) } : {}),
        ...(ep.body
          ? { body: { content: { "application/json": { schema: ep.body } } } }
          : {}),
      },
      responses,
    });
  }

  const generator = new OpenApiGeneratorV31(registry.definitions);
  return generator.generateDocument({
    openapi: "3.1.0",
    info: {
      title: "ZK-VOTE Relayer API",
      version: "1.0.0",
      description:
        "Backend relayer for anonymous voting on Stellar/Soroban. Generated from route " +
        "definitions and Zod validation schemas — see backend/API.md for prose docs and " +
        "GET /api-docs for interactive documentation.",
    },
    servers: [
      { url: "http://localhost:3001", description: "Local development" },
    ],
  });
}
