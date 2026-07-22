import {
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../database/providers/schema/user.schema';
import { Organization } from '../../organizations/entities/organization.schema';
import { Participant } from '../../organizations/participants/entities/participant.entity';
import {
  JWT_ACCESS_EXPIRES_IN,
  RefreshTokenService,
} from './refresh-token.service';

export class RefreshTokenDto {
  @ApiProperty({
    description:
      'Opaque refresh token (novo fluxo). Se omitido, usa Bearer JWT legado.',
    required: false,
  })
  @IsOptional()
  @IsString()
  refreshToken?: string;
}

type UserDoc = {
  id: string;
  name?: string;
  email?: string;
  verifiedEmail?: boolean;
  phone?: string;
  document?: string;
};

type OrgAccess = {
  accessMetadata?: unknown;
  metadata?: unknown;
  id: string;
  participantId?: string;
  role: string;
  [key: string]: unknown;
};

@Injectable()
export class RefreshTokenInfoService {
  constructor(
    @Inject('jwt-service') private readonly jwtService: JwtService,
    @InjectModel(User.name)
    private readonly userModel: Model<User>,
    @InjectModel(Organization.name)
    private readonly organizationModel: Model<Organization>,
    @InjectModel(Participant.name)
    private readonly participantModel: Model<Participant>,
    private readonly refreshTokenService: RefreshTokenService,
  ) {}

  /**
   * Novo fluxo: refresh opaco com rotação + access JWT curto (15m).
   */
  async executeByRefreshToken(refreshToken: string, withMetadata = true) {
    const userId =
      await this.refreshTokenService.findUserIdByRefreshToken(refreshToken);

    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    const userDoc = this.toUserDoc(user);

    const newRefreshToken = await this.refreshTokenService.rotateRefreshToken(
      userId,
      refreshToken,
    );

    const organizationsWithRoles = await this.loadOrganizationsWithRoles(userDoc);

    const newToken = this.jwtService.sign(
      this.buildAccessPayload(userDoc, organizationsWithRoles, withMetadata),
      { expiresIn: JWT_ACCESS_EXPIRES_IN },
    );

    return {
      name: userDoc.name,
      email: userDoc.email,
      userId: userDoc.id,
      verifiedEmail: userDoc.verifiedEmail,
      phone: userDoc.phone,
      document: userDoc.document,
      token: newToken,
      refreshToken: newRefreshToken,
      accesses: organizationsWithRoles,
    };
  }

  /**
   * Legacy: Bearer access JWT → novo access sem rotação, default do módulo (90d).
   * Shape idêntico ao contrato pré-LQDA-1738 (sem `refreshToken` na resposta).
   */
  async executeLegacy(userId: string, withMetadata = true) {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new UnauthorizedException('Invalid token');
    }
    const userDoc = this.toUserDoc(user);

    const organizationsWithRoles = await this.loadOrganizationsWithRoles(userDoc);

    // Sem expiresIn explícito → default do JwtService/módulo (90d).
    const newToken = this.jwtService.sign(
      this.buildAccessPayload(userDoc, organizationsWithRoles, withMetadata),
    );

    return {
      name: userDoc.name,
      email: userDoc.email,
      userId: userDoc.id,
      verifiedEmail: userDoc.verifiedEmail,
      phone: userDoc.phone,
      document: userDoc.document,
      token: newToken,
      accesses: organizationsWithRoles,
    };
  }

  private toUserDoc(user: {
    id?: string;
    _id?: { toString(): string };
    name?: string;
    email?: string;
    verifiedEmail?: boolean;
    phone?: string;
    document?: string;
  }): UserDoc {
    const id = user.id ?? user._id?.toString();
    if (!id) {
      throw new UnauthorizedException('Invalid user');
    }
    return {
      id,
      name: user.name,
      email: user.email,
      verifiedEmail: user.verifiedEmail,
      phone: user.phone,
      document: user.document,
    };
  }

  private buildAccessPayload(
    user: UserDoc,
    organizationsWithRoles: OrgAccess[],
    withMetadata: boolean,
  ) {
    return {
      sub: user.id,
      accesses: organizationsWithRoles.map((org) => ({
        ...org,
        accessMetadata: withMetadata ? org.accessMetadata : undefined,
        metadata: withMetadata ? org.metadata : undefined,
      })),
      name: user.name,
      email: user.email,
      verifiedEmail: user.verifiedEmail,
    };
  }

  private async loadOrganizationsWithRoles(user: UserDoc): Promise<OrgAccess[]> {
    const whereClauseOrganizationRelations: Record<string, string>[] = [];

    if (user.email) {
      whereClauseOrganizationRelations.push({ email: user.email });
    }
    if (user.document) {
      whereClauseOrganizationRelations.push({ document: user.document });
    }
    if (user.phone) {
      whereClauseOrganizationRelations.push({ phone: user.phone });
    }

    const organizationRelations =
      whereClauseOrganizationRelations.length > 0
        ? await this.participantModel.find({
            $or: whereClauseOrganizationRelations,
          })
        : [];

    const organizationIds = organizationRelations.map(
      (relation) => relation.organizationId,
    );

    const organizations = await this.organizationModel
      .find({
        $or: [{ ownerId: user.id }, { _id: { $in: organizationIds } }],
      })
      .select('id name externalId metadata');

    return organizations.map((organization) => {
      const relation = organizationRelations.find(
        (rel) => rel.organizationId === organization.id,
      );

      return {
        ...organization.toObject(),
        accessMetadata: relation?.metadata,
        id: organization.id,
        participantId: relation?.id,
        role: relation?.role || 'owner',
      };
    });
  }
}
