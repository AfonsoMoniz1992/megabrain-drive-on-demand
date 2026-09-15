import { createBrokerServer, type BrokerServerOptions } from "../../broker/src/server";

/**
 * Test-only wrapper around `createBrokerServer`.
 *
 * The broker deliberately has no default allowed root: an operator must name
 * their own harmless folder, so production construction requires the option.
 * Tests still need a stable value, so this wrapper names one explicitly rather
 * than reintroducing a silent default inside the production code path.
 */
export const TEST_ALLOWED_ROOT_NAME = "example-test-root";

export function createTestBrokerServer(options: Omit<BrokerServerOptions, "allowedRootName">) {
  return createBrokerServer({ ...options, allowedRootName: TEST_ALLOWED_ROOT_NAME });
}
