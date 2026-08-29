#!/usr/bin/env node
// MCP server (stdio transport) exposing IFF's verify() as a tool, so any
// MCP-aware agent can preflight-check an x402 v2 payment requirement
// without embedding this package as a library dependency.
//
// Uses the MCP SDK's low-level Server API (not the McpServer/zod
// convenience layer) specifically so @modelcontextprotocol/sdk stays this
// package's only dependency: the low-level API takes a plain JSON Schema
// object for a tool's inputSchema, with no zod import required on our side.
//
// Requires `npm run build` to have produced ../dist/index.js first (this is
// how a published npm package normally ships: pre-built dist/ alongside
// bin/, not rebuilt on every invocation).
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { verify, verifyAccepts } from "../dist/index.js";

const TOOL_NAME = "verify_x402_endpoint";

const server = new Server(
  { name: "iff-x402-preflight-mcp", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: TOOL_NAME,
      description:
        "Check whether an x402 v2 payment requirement for a URL is consistent with IFF's independent, signed observation of that endpoint, before paying. Never probes the URL itself and never stores the submitted requirement. Returns IFF's verify() JSON: a verdict of consistent/diverged/unobserved/stale (never a safety or trust score), plus observed evidence and history.",
      inputSchema: {
        type: "object",
        properties: {
          url: {
            type: "string",
            description: "The public HTTPS URL that returned the 402 challenge.",
          },
          payment_required: {
            type: "object",
            description:
              'The x402 v2 PaymentRequired JSON (the decoded PAYMENT-REQUIRED header, or the response body), e.g. {"x402Version":2,"accepts":[...]}. Provide this or accepts.',
          },
          accepts: {
            type: "array",
            items: { type: "object" },
            description: "Alternative to payment_required: a bare array of x402 v2 payment requirement objects.",
          },
        },
        required: ["url"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== TOOL_NAME) {
    throw new Error(`unknown tool: ${request.params.name}`);
  }
  const args = request.params.arguments ?? {};
  const { url, payment_required: paymentRequired, accepts } = args;
  if (typeof url !== "string" || url.length === 0) {
    throw new Error("url is required");
  }

  // IFF_BASE_URL overrides the SDK's production DEFAULT_BASE_URL. Leave it
  // unset for normal use.
  const options = { baseUrl: process.env.IFF_BASE_URL };
  let result;
  if (paymentRequired !== undefined) {
    result = await verify(url, paymentRequired, options);
  } else if (Array.isArray(accepts)) {
    result = await verifyAccepts(url, accepts, options);
  } else {
    throw new Error("either payment_required or accepts is required");
  }

  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
