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

    async getOrCreateDevice(ipAddress: string, userAgent: string, deviceId: string) {
        let device: Device | null = null;
        device = await this.findDeviceById(deviceId)

        if (!device) {
            await this.createDevice(deviceId, ipAddress, userAgent);
            device = await this.findDeviceById(deviceId);
        } else {
            device = await this.updateLastUseDevice(deviceId, ipAddress);
        }

        return device;
    }

    async createDevice(deviceId: string, ipAddress: string, userAgent: string) {
        const deviceHash = await this.hashDeviceId(deviceId);
        const device = await this.prisma.device.create({
            data: {
                deviceId,
                deviceHash,
                ipAddress,
                deviceName: this.getDeviceName(userAgent)
            },
        });

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

    async isGoingToBanDevice(deviceId: string, isBanned: boolean) {
        const bannedDevice = await this.prisma.device.update({
            where: { deviceId },
            data: {
                isBanned,
            }
        });

        return bannedDevice;
    }
}