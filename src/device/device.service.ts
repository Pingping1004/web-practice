import { PrismaService } from "prisma/prisma.service";
import * as crypto from 'crypto';
import { Injectable, NotFoundException } from "@nestjs/common";
import { BanSeverity, Device, DeviceStatus, TrustLevel } from "@prisma/client";
import { UAParser } from "ua-parser-js";
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class DeviceService {
    constructor(
        private readonly prisma: PrismaService,
    ) { }

    async registerDevice(userId: string, ipAddress: string, userAgent: string, deviceId: string) {
        let device: Device | null = null;
        device = await this.findDeviceById(deviceId)

        if (!device) {
            const deviceHash = await this.hashDeviceId(deviceId);
            device = await this.prisma.device.create({
                data: {
                    deviceId,
                    userId,
                    deviceHash,
                    ipAddress,
                    isMfaTrusted: false,
                    deviceStatus: DeviceStatus.Unverified,
                    trustLevel: TrustLevel.Basic,
                    deviceName: this.getDeviceName(userAgent)
                },
            });
        } else {
            device = await this.updateLastUseDevice(deviceId, ipAddress);
        }

        return device;
    }

    async updateLastUseDevice(deviceId: string, ipAddress: string) {
        const device = await this.prisma.device.update({
            where: { deviceId },
            data: { lastUsedAt: new Date(), ipAddress },
        });

        return device;
    }

    async hashDeviceId(deviceId: string): Promise<string> {
        const secret = process.env.DEVICE_ID_SECRET;
        if (!secret) throw new NotFoundException('Secret for hashing deviceId not found');
        return crypto.createHmac('sha256', secret).update(deviceId).digest('hex');
    }

    getDeviceName(userAgent: string): string {
        const parser = new UAParser(userAgent);
        const browser = parser.getBrowser();
        const os = parser.getOS();
        const device = parser.getDevice();

        const browserName = browser.name || 'Unknown Browser';
        const osName = os.name || 'Unknown OS';
        const deviceModel = device.model || '';

        if (deviceModel) {
            return `${browserName} on ${deviceModel} (${osName})`;
        }

        const deviceName = `${browserName} on ${osName}`;
        console.log('User device name: ', deviceName);
        return deviceName;
    }

    async findDeviceById(deviceId: string) {
        const device = await this.prisma.device.findUnique({
            where: { deviceId },
        });

        return device;
    }

    async verifyDevice(deviceId: string): Promise<boolean> {
        const device = await this.findDeviceById(deviceId);
        if (!device) return false;

        return Boolean(device.deviceStatus === DeviceStatus.Trusted);
    }

    // Extension for more specific device auth management according to business logic
    async updateMfaTrusted(deviceId: string) {
        const updateDevice = await this.prisma.device.update({
            where: { deviceId },
            data: {
                mfaTrustExpiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
                deviceStatus: DeviceStatus.Trusted,
                trustLevel: TrustLevel.Basic,
                isMfaTrusted: true,
                mfaLastVerifiedAt: new Date(),
            },
        });

        return updateDevice;
    }

    async setRevokeDevice(deviceId: string, isRevoked: boolean) {
        await this.prisma.device.update({
            where: { deviceId },
            data: {
                isRevoked,
            }
        });
    }

    async bannedDevice(deviceId: string, severity: BanSeverity) {
        const bannedDevice = await this.prisma.device.update({
            where: { deviceId },
            data: {
                trustLevel: TrustLevel.Blacklist,
                deviceStatus: DeviceStatus.Banned,
                banSeverity: severity,
            }
        });

        return bannedDevice;
    }

    async unbannedDevice(deviceId: string) {
        const unbannedDevice = await this.prisma.device.update({
            where: { deviceId },
            data: {
                deviceStatus: DeviceStatus.Unverified,
                banSeverity: null,
                trustLevel: TrustLevel.Basic,
            }
        });

        return unbannedDevice;
    }
}