/**
 * Revenue Module
 *
 * Enables automaton to earn USDC by providing paid services.
 * This module implements the missing "earning" side of the x402 protocol.
 *
 * @module revenue
 */

export { createX402Server, USDC_ADDRESS } from "./x402-server.js";
export type { X402ServerOptions } from "./x402-server.js";
