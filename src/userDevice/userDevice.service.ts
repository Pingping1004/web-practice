import { Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { PrismaService } from "prisma/prisma.service";
import { CreateUserDeviceDto } from "./dto/userDevice.dto";
import { DeviceStatus, TrustLevel, UserDevice } from "@prisma/client";

@Injectable()
export class UserDeviceService {
    constructor(
        private readonly prisma: PrismaService,
    ) { }

    async getOrCreateUserDevice(
        userId: string, deviceId: string, deviceStatus: DeviceStatus = "Unverified", trustLevel: TrustLevel = "Basic"
    ) {
        let userDevice: UserDevice | null = null;
        userDevice = await this.findUserDevice(userId, deviceId)

        if (!userDevice) {
            await this.createUserDevice(userId, deviceId, deviceStatus, trustLevel);
            userDevice = await this.findUserDevice(userId, deviceId);
        } else {
            userDevice = await this.updateLastUsedUserDevice(userDevice.userId, userDevice.deviceId, userDevice.userDeviceId);
        }

        if (!userDevice) throw new InternalServerErrorException('Failed to get or create user device');

        return userDevice;
    }

    async createUserDevice(userId: string, deviceId: string, deviceStatus: DeviceStatus, trustLevel: TrustLevel) {
        const newDevice = await this.prisma.userDevice.create({
            data: { userId, deviceId, deviceStatus, trustLevel }
        });

        return newDevice;
    }

    async updateLastUsedUserDevice(userId: string, deviceId: string, userDeviceId: string) {
        await this.isOwnerOfUserDevice(userId, deviceId);

        const userDevice = await this.prisma.userDevice.update({
            where: { userDeviceId },
            data: { lastUsedAt: new Date() },
        });

        return userDevice;
    }

    async revokedUserDevice(userDeviceId: string, reason: string) {
        await this.prisma.userDevice.update({
            where: { userDeviceId },
            data: {
                isRevoked: true,
                revokedReason: reason,
            },
        });
    }

    async revokedAllUserDevices(userId: string, reason: string) {
        await this.prisma.userDevice.updateMany({
            where: { userId },
            data: {
                isRevoked: true,
                revokedReason: reason,
            }
        });
    }

    async findUserDevice(userId: string, deviceId: string) {
        const userDevice = await this.prisma.userDevice.findFirst({
            where: { userId, deviceId },
            orderBy: { lastUsedAt: "desc" },
        });

        return userDevice;
    }

    async findAllDevicesOfUser(userId: string) {
        const alluserDevices = await this.prisma.userDevice.findMany({
            where: { userId },
            orderBy: { lastUsedAt: "desc" },
            include: { device: true },
        });

        return alluserDevices;
    }

    async isOwnerOfUserDevice(userId: string, deviceId: string): Promise<boolean> {
        const existingUserDevice = await this.findUserDevice(userId, deviceId);
        if (!existingUserDevice) throw new NotFoundException(`User device not found`);

        if (userId !== existingUserDevice.userId || deviceId !== existingUserDevice.deviceId) {
            throw new UnauthorizedException(`You cannnot update other users' MFA trusted status`);
        }

        return true;
    }

    async isUserDeviceVerified(userId: string, deviceId: string): Promise<boolean> {
        const userDevice = await this.findUserDevice(userId, deviceId);

        if (!userDevice) throw new NotFoundException('Not found device to verify');
        if (!userDevice.mfaLastVerifiedAt || !userDevice.mfaTrustExpiresAt) return false;

        const isVerified = userDevice.deviceStatus !== DeviceStatus.Banned &&
            userDevice.isMfaTrusted && userDevice?.mfaTrustExpiresAt > new Date();

        return !!isVerified;
    }

    async markUserDeviceAsVerified(userId: string, deviceId: string, userDeviceId: string) {
        await this.isOwnerOfUserDevice(userId, deviceId);

        const updateMfaUserDevice = await this.prisma.userDevice.update({
            where: { userDeviceId },
            data: {
                mfaTrustExpiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
                deviceStatus: DeviceStatus.Trusted,
                trustLevel: TrustLevel.Basic,
                isMfaTrusted: true,
                mfaLastVerifiedAt: new Date(),
            },
        });

        return updateMfaUserDevice;
    }
}