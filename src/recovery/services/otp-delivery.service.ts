import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Participant } from '../../organizations/participants/entities/participant.entity';

const OTP_MESSAGE_TTL_HINT = 'Válido por 10 minutos.';

export type OtpChannel = 'whatsapp' | 'sms';

export type DeliverOtpParams = {
  userId: string;
  email: string;
  name: string;
  code: string;
  phone?: string | null;
  organizationId?: string;
};

@Injectable()
export class OtpDeliveryService {
  constructor(
    private readonly jwtService: JwtService,
    @InjectModel(Participant.name)
    private readonly participantModel: Model<Participant>,
  ) {}

  async deliver(params: DeliverOtpParams): Promise<boolean> {
    const phoneChannel = await this.resolvePhone(
      params.userId,
      params.phone,
      params.organizationId,
    );

    if (phoneChannel?.phone) {
      const sent = await this.sendViaOmni({
        organizationId: phoneChannel.organizationId,
        phone: phoneChannel.phone,
        code: params.code,
        channel: 'whatsapp',
      });
      if (sent) {
        return true;
      }
      const smsSent = await this.sendViaOmni({
        organizationId: phoneChannel.organizationId,
        phone: phoneChannel.phone,
        code: params.code,
        channel: 'sms',
      });
      if (smsSent) {
        return true;
      }
    }

    return this.sendViaEmail(params);
  }

  async resolvePhone(
    userId: string,
    userPhone?: string | null,
    organizationId?: string,
  ): Promise<{ organizationId: string; phone: string } | null> {
    const requestedOrg = organizationId?.trim();

    if (requestedOrg) {
      const membership = await this.participantModel
        .findOne({
          userId,
          organizationId: requestedOrg,
          $or: [{ deletedAt: { $exists: false } }, { deletedAt: null }],
        })
        .select('phone organizationId')
        .lean()
        .exec();

      if (!membership) {
        return null;
      }

      if (userPhone?.trim()) {
        return { organizationId: requestedOrg, phone: userPhone.trim() };
      }

      if (membership.phone) {
        return {
          organizationId: String(membership.organizationId || requestedOrg),
          phone: String(membership.phone),
        };
      }

      return null;
    }

    if (userPhone?.trim()) {
      const orgId = await this.resolveOrganizationId(userId);
      if (!orgId) {
        return null;
      }
      return { organizationId: orgId, phone: userPhone.trim() };
    }

    const participant = await this.participantModel
      .findOne({
        userId,
        phone: { $exists: true, $nin: [null, ''] },
        $or: [{ deletedAt: { $exists: false } }, { deletedAt: null }],
      })
      .select('phone organizationId')
      .lean()
      .exec();

    if (!participant?.phone || !participant.organizationId) {
      return null;
    }

    return {
      organizationId: String(participant.organizationId),
      phone: String(participant.phone),
    };
  }

  private async resolveOrganizationId(userId: string): Promise<string | null> {
    const participant = await this.participantModel
      .findOne({
        userId,
        $or: [{ deletedAt: { $exists: false } }, { deletedAt: null }],
      })
      .select('organizationId')
      .lean()
      .exec();
    return participant?.organizationId
      ? String(participant.organizationId)
      : null;
  }

  private async sendViaOmni(params: {
    organizationId: string;
    phone: string;
    channel: OtpChannel;
    code: string;
  }): Promise<boolean> {
    const omniBase = process.env.OMNI_CHANNEL_API_URL?.trim();
    const jwtSecret = process.env.JWT_SECRET;
    if (!omniBase || !jwtSecret) {
      return false;
    }

    try {
      const token = this.jwtService.sign(
        { sub: 'sales-management-service', service: true },
        { secret: jwtSecret, expiresIn: '5m' },
      );

      const baseUrl = omniBase.replace(/\/$/, '');
      const response = await fetch(`${baseUrl}/internal/otp/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          companyId: params.organizationId,
          phone: params.phone,
          channel: params.channel,
          code: params.code,
        }),
      });

      if (response.ok) {
        return true;
      }

      console.warn(
        `OTP /internal/otp/send failed: ${response.status} (${params.channel})`,
      );
    } catch (err) {
      console.warn('OTP /internal/otp/send error:', err);
    }
    return false;
  }

  private async sendViaEmail(params: DeliverOtpParams): Promise<boolean> {
    const emailServiceUrl = process.env.EMAIL_VERIFICATION_SENDER_URL?.trim();
    if (!emailServiceUrl) {
      return false;
    }

    const emailPayload = {
      data: {
        passwordToken: params.code,
        name: params.name,
        subject: 'Recuperação de Senha',
        ttlHint: OTP_MESSAGE_TTL_HINT,
      },
      email: params.email,
      template: 'recovery-password-code',
    };

    try {
      const response = await fetch(`${emailServiceUrl}/emails`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(emailPayload),
      });
      return response.ok;
    } catch (err) {
      console.warn('OTP email delivery error:', err);
      return false;
    }
  }
}
