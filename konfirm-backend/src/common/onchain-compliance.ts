import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  Contract,
  Networks,
  SorobanRpc,
  TransactionBuilder,
  nativeToScVal,
  Address,
  Keypair,
  xdr,
} from '@stellar/stellar-sdk';

/**
 * Thin client around the deployed compliance contract.
 *
 * Read path: `is_allowed` (used by payments/x402 hot paths).
 * Write path: `block_address` / `allow_address` / `clear_address` (used by the
 * admin block/unblock flow so the on-chain blocklist is actually populated).
 */
@Injectable()
export class OnchainComplianceService {
  private readonly logger = new Logger(OnchainComplianceService.name);
  private readonly server: SorobanRpc.Server;
  private readonly contractId: string;
  private readonly networkPassphrase: string;
  private readonly adminKeypair: Keypair | null;

  constructor(private readonly config: ConfigService) {
    const rpcUrl = this.config.get<string>('SOROBAN_RPC_URL') ?? 'https://soroban-testnet.stellar.org';
    this.server = new SorobanRpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') });
    this.contractId = this.config.get<string>('COMPLIANCE_CONTRACT_ID') ?? '';
    this.networkPassphrase =
      this.config.get<string>('STELLAR_NETWORK_PASSPHRASE') ?? Networks.TESTNET;

    const secret = this.config.get<string>('COMPLIANCE_ADMIN_SECRET');
    this.adminKeypair = secret ? Keypair.fromSecret(secret) : null;
  }

  async isAllowed(address: string): Promise<boolean> {
    try {
      const contract = new Contract(this.contractId);
      const account = await this.server.getAccount(
        this.adminKeypair?.publicKey() ?? address,
      );
      const tx = new TransactionBuilder(account, {
        fee: '100',
        networkPassphrase: this.networkPassphrase,
      })
        .addOperation(
          contract.call('is_allowed', new Address(address).toScVal()),
        )
        .setTimeout(30)
        .build();

      const sim = await this.server.simulateTransaction(tx);
      if (SorobanRpc.Api.isSimulationError(sim)) {
        this.logger.warn(`is_allowed simulation failed for ${address}: ${sim.error}`);
        return true;
      }
      const retval = (sim as SorobanRpc.Api.SimulateTransactionSuccessResponse).result?.retval;
      return retval ? retval.b() : true;
    } catch (err) {
      this.logger.warn(`is_allowed RPC error for ${address}: ${(err as Error).message}`);
      return true;
    }
  }

  /** Block an address on-chain via `block_address`. */
  async blockAddress(address: string): Promise<void> {
    await this.invokeMutator('block_address', address);
  }

  /** Allow an address on-chain via `allow_address`. */
  async allowAddress(address: string): Promise<void> {
    await this.invokeMutator('allow_address', address);
  }

  /** Clear an address's compliance entry on-chain via `clear_address`. */
  async clearAddress(address: string): Promise<void> {
    await this.invokeMutator('clear_address', address);
  }

  private async invokeMutator(method: string, address: string): Promise<void> {
    if (!this.adminKeypair) {
      throw new Error(
        `Cannot call ${method}: COMPLIANCE_ADMIN_SECRET is not configured`,
      );
    }
    const contract = new Contract(this.contractId);
    const account = await this.server.getAccount(this.adminKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(contract.call(method, new Address(address).toScVal()))
      .setTimeout(30)
      .build();

    const prepared = await this.server.prepareTransaction(tx);
    prepared.sign(this.adminKeypair);

    const sendResp = await this.server.sendTransaction(prepared);
    if (sendResp.status === 'ERROR') {
      throw new Error(`${method} submission failed for ${address}`);
    }

    let status = sendResp.status;
    let hash = sendResp.hash;
    while (status === 'PENDING' || status === 'TRY_AGAIN_LATER') {
      await new Promise((r) => setTimeout(r, 1000));
      const result = await this.server.getTransaction(hash);
      status = result.status as typeof status;
      if (status === 'SUCCESS') return;
      if (status === 'FAILED') {
        throw new Error(`${method} transaction ${hash} failed for ${address}`);
      }
    }
  }
}
