import { PrismaService } from "prisma/prisma.service";
import * as crypto from 'crypto';
import { Injectable, NotFoundException } from "@nestjs/common";
import { BanSeverity, DeviceStatus, TrustLevel } from "@prisma/client";

@Injectable()
export class DeviceService {
    constructor(
        private readonly prisma: PrismaService,
    ) { }

    async registerDevice(userId: string, ipAddress: string, deviceId: string) {
        const deviceHash = await this.hashDeviceId(deviceId);

        let device = await this.findDevice(userId, deviceHash);
        if (!device) {
            device = await this.prisma.device.create({
                data: {
                    userId,
                    deviceHash,
                    ipAddress,
                    deviceStatus: DeviceStatus.Trusted,
                    trustLevel: TrustLevel.Basic,
                },
            });
        } else {
            device = await this.prisma.device.update({
                where: { userId_deviceHash: { userId, deviceHash } },
                data: { lastUsedAt: new Date(), ipAddress },
            });
        }

        return device;
    }

    async hashDeviceId(deviceId: string): Promise<string> {
        const secret = process.env.DEVICE_ID_SECRET;
        if (!secret) throw new NotFoundException('Secret for hashing deviceId not found');
        return crypto.createHmac('sha256', secret).update(deviceId).digest('hex');
    }

    async findDevice(userId: string, deviceHash: string) {
        const device = await this.prisma.device.findUnique({
            where: { userId_deviceHash: { userId, deviceHash } },
        });

        console.log('Device found: ', device);
        return device || null;
    }

    async verifyDevice(userId: string, deviceHash: string): Promise<boolean> {
        const device = await this.findDevice(userId, deviceHash);
        if (!device) return false;

        return device?.deviceStatus === DeviceStatus.Trusted;
    }

    // Extension for more specific device auth management according to business logic
    async updateDeviceStatus(
        userId: string, ipAddress: string, deviceId: string, status: DeviceStatus, trustLevel: TrustLevel
    ) {
        const updateDevice = await this.prisma.device.update({
            where: { userId, ipAddress, deviceId },
            data: {
                deviceStatus: status,
                trustLevel,
            }
        });

        return updateDevice.deviceStatus;
    }

    async bannedDevice(userId: string, ipAddress: string, deviceId: string, severity: BanSeverity) {
        const bannedDevice = await this.prisma.device.update({
            where: { userId, ipAddress, deviceId },
            data: {
                trustLevel: TrustLevel.Blacklist,
                deviceStatus: DeviceStatus.Banned,
                banSeverity: severity,
            }
        });

        return bannedDevice;
    }

    async unbannedDevice(userId: string, ipAddress: string, deviceId: string) {
        const unbannedDevice = await this.prisma.device.update({
            where: { userId, ipAddress, deviceId },
            data: {
                deviceStatus: DeviceStatus.Unverified,
                banSeverity: null,
                trustLevel: TrustLevel.Basic,
            }
        });

        return unbannedDevice;
    }
}