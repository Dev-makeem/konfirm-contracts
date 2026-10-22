import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { BlockedAddress } from './entities/blocked-address.entity';
import { OnchainComplianceClient } from '../common/onchain-compliance';

@Injectable()
export class AdminComplianceService {
  private readonly logger = new Logger(AdminComplianceService.name);

  constructor(
    @InjectRepository(BlockedAddress)
    private readonly blockedAddressRepo: Repository<BlockedAddress>,
    private readonly onchainCompliance: OnchainComplianceClient,
  ) {}

  async listBlockedAddresses(): Promise<BlockedAddress[]> {
    return this.blockedAddressRepo.find({ order: { createdAt: 'DESC' } });
  }

  async blockAddress(address: string, reason?: string): Promise<BlockedAddress> {
    const existing = await this.blockedAddressRepo.findOne({ where: { address } });
    if (existing) {
      return existing;
    }

    const blocked = this.blockedAddressRepo.create({ address, reason });
    const saved = await this.blockedAddressRepo.save(blocked);

    // Mirror the block on-chain so the deployed compliance contract's
    // `is_allowed` gate reflects the same source of truth as Postgres.
    try {
      await this.onchainCompliance.blockAddress(address);
    } catch (err) {
      this.logger.error(
        `Failed to block address ${address} on-chain: ${(err as Error).message}`,
      );
    }

    return saved;
  }

  async unblockAddress(address: string): Promise<void> {
    const existing = await this.blockedAddressRepo.findOne({ where: { address } });
    if (!existing) {
      throw new NotFoundException(`Blocked address ${address} not found`);
    }

    await this.blockedAddressRepo.remove(existing);

    // Clear the on-chain block so the compliance contract allows the address again.
    try {
      await this.onchainCompliance.clearAddress(address);
    } catch (err) {
      this.logger.error(
        `Failed to clear address ${address} on-chain: ${(err as Error).message}`,
      );
    }
  }
}
