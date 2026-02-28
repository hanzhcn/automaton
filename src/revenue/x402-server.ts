/**
 * x402 Payment Server
 *
 * Enables automaton to receive USDC payments for services.
 * This is the missing "earning" side of the x402 protocol.
 */

import http from "http";
import {
  createPublicClient,
  createWalletClient,
  http as viemHttp,
  recoverTypedDataAddress,
  type Address,
  type Hex,
  type PrivateKeyAccount,
} from "viem";
import { base } from "viem/chains";

// USDC contract on Base mainnet
const USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as Address;

// Base chain ID
const BASE_CHAIN_ID = 8453;

// EIP-712 domain for USDC TransferWithAuthorization
const USDC_DOMAIN = {
  name: "USD Coin",
  version: "2",
  chainId: BASE_CHAIN_ID,
  verifyingContract: USDC_ADDRESS,
} as const;

// EIP-712 types for TransferWithAuthorization
const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

// Payment requirement structure (x402 v1 spec)
interface PaymentRequirement {
  scheme: "exact";
  network: "eip155:8453";
  maxAmountRequired: string; // atomic units (6 decimals)
  payToAddress: Address;
  usdcAddress: Address;
  requiredDeadlineSeconds: number;
}

interface X402PaymentHeader {
  x402Version: number;
  accepts: PaymentRequirement[];
}

interface IncomingPayment {
  x402Version?: number;
  scheme?: string;
  network?: string;
  payload: {
    signature: Hex;
    authorization: {
      from: Address;
      to: Address;
      value: string;
      validAfter: string;
      validBefore: string;
      nonce: string;
    };
  };
}

// Nonce tracking for replay protection (in-memory, should use Redis in production)
const usedNonces = new Set<string>();

/**
 * Create a 402 Payment Required response
 */
function createPaymentResponse(
  res: http.ServerResponse,
  amountUsd: number,
  payTo: Address
): void {
  // Convert USD to atomic units (6 decimals)
  const atomicAmount = Math.floor(amountUsd * 1_000_000).toString();

  const requirement: PaymentRequirement = {
    scheme: "exact",
    network: "eip155:8453",
    maxAmountRequired: atomicAmount,
    payToAddress: payTo,
    usdcAddress: USDC_ADDRESS,
    requiredDeadlineSeconds: 300, // 5 minutes
  };

  const header: X402PaymentHeader = {
    x402Version: 1,
    accepts: [requirement],
  };

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64");

  res.writeHead(402, {
    "X-Payment-Required": encodedHeader,
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  });

  res.end(
    JSON.stringify({
      error: "Payment required",
      accepts: [requirement],
    })
  );
}

/**
 * Verify incoming payment signature using EIP-712
 */
async function verifyPaymentSignature(payment: IncomingPayment): Promise<{
  valid: boolean;
  error?: string;
  recoveredAddress?: Address;
}> {
  const { payload } = payment;
  const { authorization, signature } = payload;

  // 1. Check required fields
  if (!authorization || !signature) {
    return { valid: false, error: "Missing authorization or signature" };
  }

  // 2. Check time window
  const now = Math.floor(Date.now() / 1000);
  const validAfter = parseInt(authorization.validAfter, 10);
  const validBefore = parseInt(authorization.validBefore, 10);

  if (now < validAfter) {
    return { valid: false, error: "Payment not yet valid" };
  }
  if (now > validBefore) {
    return { valid: false, error: "Payment has expired" };
  }

  // 3. Check nonce uniqueness (prevent replay attacks)
  if (usedNonces.has(authorization.nonce)) {
    return { valid: false, error: "Nonce already used (replay attack)" };
  }

  // 4. Construct EIP-712 message
  const message = {
    from: authorization.from,
    to: authorization.to,
    value: BigInt(authorization.value),
    validAfter: BigInt(authorization.validAfter),
    validBefore: BigInt(authorization.validBefore),
    nonce: authorization.nonce as Hex,
  };

  // 5. Recover signer address from signature
  try {
    const recoveredAddress = await recoverTypedDataAddress({
      domain: USDC_DOMAIN,
      types: TRANSFER_WITH_AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message,
      signature,
    });

    // 6. Verify recovered address matches authorization.from
    if (recoveredAddress.toLowerCase() !== authorization.from.toLowerCase()) {
      return {
        valid: false,
        error: "Signature does not match payer address",
        recoveredAddress,
      };
    }

    // 7. Mark nonce as used
    usedNonces.add(authorization.nonce);

    return { valid: true, recoveredAddress };
  } catch (err) {
    return {
      valid: false,
      error: `Signature verification failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Verify incoming payment header
 */
function parsePaymentHeader(paymentHeader: string): IncomingPayment | null {
  try {
    const decoded = Buffer.from(paymentHeader, "base64").toString();
    const payment: IncomingPayment = JSON.parse(decoded);

    // Basic validation
    if (!payment.payload?.authorization || !payment.payload?.signature) {
      return null;
    }

    return payment;
  } catch {
    return null;
  }
}

/**
 * Execute the payment on-chain using USDC.transferWithAuthorization
 * This submits the signed authorization to the USDC contract
 *
 * @param payment - The payment payload with authorization and signature
 * @param account - Optional wallet account to submit the transaction (pays gas)
 *                  If not provided, payment is validated but not executed on-chain
 */
async function executePayment(
  payment: IncomingPayment,
  account?: PrivateKeyAccount
): Promise<{
  success: boolean;
  txHash?: Hex;
  error?: string;
}> {
  const { payload } = payment;
  const { authorization, signature } = payload;

  try {
    // USDC ABI for transferWithAuthorization (EIP-3009)
    const USDC_ABI = [
      {
        inputs: [
          { name: "from", type: "address" },
          { name: "to", type: "address" },
          { name: "value", type: "uint256" },
          { name: "validAfter", type: "uint256" },
          { name: "validBefore", type: "uint256" },
          { name: "nonce", type: "bytes32" },
          { name: "v", type: "uint8" },
          { name: "r", type: "bytes32" },
          { name: "s", type: "bytes32" },
        ],
        name: "transferWithAuthorization",
        outputs: [],
        stateMutability: "nonpayable",
        type: "function",
      },
    ] as const;

    // Parse signature into v, r, s components
    // EIP-712 signature is 65 bytes: r (32) + s (32) + v (1)
    const sig = signature.slice(2); // Remove 0x prefix
    const r = `0x${sig.slice(0, 64)}` as Hex;
    const s = `0x${sig.slice(64, 128)}` as Hex;
    const v = parseInt(sig.slice(128, 130), 16);

    // If no account provided, validate but don't execute on-chain
    if (!account) {
      console.log("[REVENUE] Payment validated (on-chain execution skipped - no account):", {
        from: authorization.from,
        to: authorization.to,
        value: `${parseInt(authorization.value, 10) / 1_000_000} USDC`,
        nonce: authorization.nonce,
      });
      return { success: true };
    }

    // Create wallet client for on-chain execution
    const walletClient = createWalletClient({
      account,
      chain: base,
      transport: viemHttp(undefined, { timeout: 30_000 }),
    });

    // Execute the transfer on-chain
    const txHash = await walletClient.writeContract({
      address: USDC_ADDRESS,
      abi: USDC_ABI,
      functionName: "transferWithAuthorization",
      args: [
        authorization.from,
        authorization.to,
        BigInt(authorization.value),
        BigInt(authorization.validAfter),
        BigInt(authorization.validBefore),
        authorization.nonce as Hex,
        v,
        r,
        s,
      ],
    });

    console.log("[REVENUE] Payment executed on-chain:", {
      txHash,
      from: authorization.from,
      to: authorization.to,
      value: `${parseInt(authorization.value, 10) / 1_000_000} USDC`,
    });

    return { success: true, txHash };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    console.error("[REVENUE] Payment execution error:", errorMessage);
    return { success: false, error: errorMessage };
  }
}

export interface X402ServerOptions {
  port: number;
  payToAddress: Address;
  priceUsd: number;
  serviceName: string;
  /** Optional wallet account to execute payments on-chain (pays gas on Base) */
  account?: PrivateKeyAccount;
  onPayment?: (payment: IncomingPayment, amount: number) => void;
  onService?: (path: string) => Promise<any>;
}

/**
 * Create and start x402 payment server
 */
export function createX402Server(options: X402ServerOptions): http.Server {
  const { port, payToAddress, priceUsd, serviceName, account, onPayment, onService } =
    options;

  const server = http.createServer(async (req, res) => {
    const path = req.url || "/";
    const paymentHeader = req.headers["x-payment"] as string | undefined;

    // CORS preflight
    if (req.method === "OPTIONS") {
      res.writeHead(200, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "X-Payment",
      });
      res.end();
      return;
    }

    // No payment header - request payment
    if (!paymentHeader) {
      console.log(`[REVENUE] Payment required for ${path}`);
      createPaymentResponse(res, priceUsd, payToAddress);
      return;
    }

    // Parse payment header
    const payment = parsePaymentHeader(paymentHeader);
    if (!payment) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid payment format" }));
      return;
    }

    // Verify payment signature (EIP-712)
    const verification = await verifyPaymentSignature(payment);
    if (!verification.valid) {
      console.error(`[REVENUE] Payment verification failed: ${verification.error}`);
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: verification.error || "Invalid signature" }));
      return;
    }

    // Execute payment on-chain (if account provided)
    const execution = await executePayment(payment, account);
    if (!execution.success) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: execution.error || "Payment execution failed" }));
      return;
    }

    // Record revenue
    const amount = parseFloat(payment.payload.authorization.value) / 1_000_000;
    console.log(`[REVENUE] Received $${amount} for ${serviceName}`);

    if (onPayment) {
      onPayment(payment, amount);
    }

    // Execute service
    if (onService) {
      try {
        const result = await onService(path);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
      } catch (error) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: error instanceof Error ? error.message : "Service error",
          })
        );
      }
    } else {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true, service: serviceName, txHash: execution.txHash }));
    }
  });

  server.listen(port, () => {
    console.log(`[REVENUE] x402 server listening on port ${port}`);
    console.log(`[REVENUE] Service: ${serviceName} @ $${priceUsd}/request`);
    console.log(`[REVENUE] Receiving address: ${payToAddress}`);
    if (account) {
      console.log(`[REVENUE] On-chain execution: enabled (gas payer: ${account.address})`);
    } else {
      console.log(`[REVENUE] On-chain execution: disabled (signature validation only)`);
    }
  });

  return server;
}

export { USDC_ADDRESS };
