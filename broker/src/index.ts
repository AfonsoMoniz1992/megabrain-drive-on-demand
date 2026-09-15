import type { Server } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createAdminServer } from "./admin-server.js";
import {
  deriveEnrollmentStoreKey,
  EncryptedEnrollmentRecordStore
} from "./enrollment-record-store.js";
import { EnrollmentStore } from "./enrollment-store.js";
import { PairingStore } from "./pairing-store.js";
import { createPrivateApiGateway } from "./private-api-gateway.js";
import { createPublicGateway } from "./public-gateway.js";
import { deriveRefreshTokenStoreKey, EncryptedRefreshTokenStore } from "./refresh-token-store.js";
import { loadBrokerRuntimeEnvironment, type BrokerRuntimeEnvironment } from "./runtime-secrets.js";
import { createBrokerServer } from "./server.js";

/**
 * Broker deployment entrypoint.
 *
 * Deployment shape: the broker is a LOOPBACK core (OAuth callback + pairing/
 * lease API) and the operator-only ADMIN surface (enrollment minting,
 * revocation) is a separate loopback HTTP server. Secrets arrive as
 * protected files (see runtime-secrets), are held only in memory and are never
 * logged: the startup lines below carry ports and file paths only.
 *
 * The public gateway is OAuth callback-only: its public public reverse proxy path mount
 * forwards exactly one callback path and returns 404 for every API route.
 * A separate PRIVATE API gateway is required for the private network Serve mount; it
 * forwards only pair, claim, nonce and lease to the loopback broker. Neither
 * gateway ever exposes the admin surface.
 *
 * Importing this module has no side effects; the process starts only when the
 * built file is executed directly (`npm run broker:start`).
 */

/** Non-secret, loggable startup facts. Deliberately excludes every credential. */
export interface BrokerStartupFacts {
  publicPort: number;
  adminPort: number;
  gatewayPort: number;
  privateGatewayPort: number;
  googleCallbackUri: string;
  refreshTokenFilePath: string;
  enrollmentFilePath: string;
}

export interface BrokerDeployment {
  runtime: BrokerRuntimeEnvironment;
  publicServer: Server;
  adminServer: Server;
  gatewayServer: Server;
  privateGatewayServer: Server;
  facts: BrokerStartupFacts;
}

export interface StartedBrokerDeployment extends BrokerDeployment {
  /** Stops all four listeners; resolves once none is accepting connections. */
  close(): Promise<void>;
}

/**
 * Builds the full deployment without binding a port, then runs a fail-fast
 * store preflight. The preflight reads both encrypted stores once so an
 * unprotected directory, a foreign-owned path or a record that cannot be
 * decrypted with the injected key stops the service at startup instead of at
 * the first real enrollment. Nothing is created: a missing store directory is
 * still left to first use, and a wider pre-existing one is tightened to 0700.
 */
export async function composeBrokerDeployment(
  env: Record<string, string | undefined>
): Promise<BrokerDeployment> {
  const runtime = await loadBrokerRuntimeEnvironment(env);

  // One operator-injected master key, two distinct HKDF-derived store keys: the
  // refresh-token store and the enrollment record store never share a key.
  const refreshTokenStore = new EncryptedRefreshTokenStore(
    runtime.refreshTokenFilePath,
    deriveRefreshTokenStoreKey(runtime.tokenKey)
  );
  const enrollmentRecordStore = new EncryptedEnrollmentRecordStore(
    runtime.enrollmentFilePath,
    deriveEnrollmentStoreKey(runtime.tokenKey)
  );
  const pairingStore = new PairingStore(undefined, runtime.config.pairingCapacity);
  const enrollmentStore = new EnrollmentStore();

  // Fail-fast preflight before any listener is bound.
  await refreshTokenStore.read();
  await enrollmentRecordStore.count();

  const publicServer = createBrokerServer({
    oauth: { config: runtime.config, clientSecret: runtime.clientSecret },
    refreshTokenStore,
    enrollmentRecordStore,
    pairingStore,
    enrollmentStore,
    allowedRootName: runtime.allowedRootName,
    maxPairAttemptsPerWindow: runtime.config.pairingRateLimitMaxAttempts,
    rateLimitWindowMs: runtime.config.pairingRateLimitWindowMs
  });

  const adminServer = createAdminServer({
    adminToken: runtime.adminToken,
    enrollmentStore,
    enrollmentRecordStore,
    pairingStore,
    refreshTokenStore
  });

  // Public gateway: OAuth callback only. It never talks to the admin surface.
  const gatewayServer = createPublicGateway({
    upstream: `http://127.0.0.1:${runtime.publicPort}`
  });
  // Private gateway: private network Serve API-only allow-list. It never exposes the
  // public callback, health or admin surface.
  const privateGatewayServer = createPrivateApiGateway({
    upstream: `http://127.0.0.1:${runtime.publicPort}`
  });

  return {
    runtime,
    publicServer,
    adminServer,
    gatewayServer,
    privateGatewayServer,
    facts: {
      publicPort: runtime.publicPort,
      adminPort: runtime.adminPort,
      gatewayPort: runtime.gatewayPort,
      privateGatewayPort: runtime.privateGatewayPort,
      googleCallbackUri: runtime.config.googleCallbackUri,
      refreshTokenFilePath: runtime.refreshTokenFilePath,
      enrollmentFilePath: runtime.enrollmentFilePath
    }
  };
}

function listenOnLoopback(server: Server, port: number): Promise<void> {
  return new Promise<void>((resolveListen, rejectListen) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      rejectListen(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolveListen();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    // Loopback only: neither surface is ever bound to a public interface.
    server.listen(port, "127.0.0.1");
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise<void>((resolveClose) => {
    if (!server.listening) {
      resolveClose();
      return;
    }
    server.close(() => resolveClose());
  });
}

/** Composes the deployment and binds all loopback listeners to 127.0.0.1. */
export async function startBrokerDeployment(
  env: Record<string, string | undefined>
): Promise<StartedBrokerDeployment> {
  const deployment = await composeBrokerDeployment(env);
  const close = async (): Promise<void> => {
    await Promise.all([
      closeServer(deployment.publicServer),
      closeServer(deployment.adminServer),
      closeServer(deployment.gatewayServer),
      closeServer(deployment.privateGatewayServer)
    ]);
  };

  try {
    await listenOnLoopback(deployment.publicServer, deployment.facts.publicPort);
  } catch (error) {
    await close();
    throw error;
  }
  try {
    await listenOnLoopback(deployment.adminServer, deployment.facts.adminPort);
  } catch (error) {
    await close();
    throw error;
  }
  try {
    await listenOnLoopback(deployment.gatewayServer, deployment.facts.gatewayPort);
  } catch (error) {
    await close();
    throw error;
  }
  try {
    await listenOnLoopback(deployment.privateGatewayServer, deployment.facts.privateGatewayPort);
  } catch (error) {
    await close();
    throw error;
  }

  return { ...deployment, close };
}

/**
 * Production entrypoint. Returns 0 once all listeners are up, 1 on any
 * configuration or bind failure (with a single clear, secret-free message).
 */
export async function runBrokerEntrypoint(env: Record<string, string | undefined>): Promise<number> {
  let started: StartedBrokerDeployment;
  try {
    started = await startBrokerDeployment(env);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "unknown error";
    console.error(`gdrive-stream-broker failed to start: ${reason}`);
    return 1;
  }

  // Non-secret startup facts only. No token, secret, key or enrollment code is
  // ever logged, and no request field is logged by either server.
  console.info(`gdrive-stream-broker listening on 127.0.0.1:${started.facts.publicPort}`);
  console.info(`gdrive-stream-broker admin surface on 127.0.0.1:${started.facts.adminPort}`);
  console.info(`gdrive-stream-broker public gateway on 127.0.0.1:${started.facts.gatewayPort}`);
  console.info(`gdrive-stream-broker private API gateway on 127.0.0.1:${started.facts.privateGatewayPort}`);
  console.info(`gdrive-stream-broker oauth callback: ${started.facts.googleCallbackUri}`);
  console.info(`gdrive-stream-broker refresh token store: ${started.facts.refreshTokenFilePath}`);
  console.info(`gdrive-stream-broker enrollment store: ${started.facts.enrollmentFilePath}`);

  let shuttingDown = false;
  const shutdown = (): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    started.close().then(
      () => process.exit(0),
      () => process.exit(1)
    );
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);

  return 0;
}

/** True only when this module is the Node entrypoint, never on import. */
function isDirectInvocation(): boolean {
  const entry = process.argv[1];
  if (typeof entry !== "string" || entry.length === 0) return false;
  try {
    return resolve(entry) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isDirectInvocation()) {
  void runBrokerEntrypoint(process.env).then((exitCode) => {
    if (exitCode !== 0) process.exitCode = exitCode;
  });
}
