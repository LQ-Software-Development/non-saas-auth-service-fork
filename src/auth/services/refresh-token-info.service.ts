import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';
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
  @ApiProperty({ description: 'Opaque refresh token' })
  @IsNotEmpty()
  @IsString()
  refreshToken: string;
}

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

  async execute(
    refreshToken: string,
    withMetadata = true,
  ) {
    const userId =
      await this.refreshTokenService.findUserIdByRefreshToken(refreshToken);

    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const newRefreshToken = await this.refreshTokenService.rotateRefreshToken(
      userId,
      refreshToken,
    );

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

    const organizationsWithRoles = organizations.map((organization) => {
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

    const newToken = this.jwtService.sign(
      {
        sub: user.id,
        accesses: organizationsWithRoles.map((org) => ({
          ...org,
          accessMetadata: withMetadata ? org.accessMetadata : undefined,
          metadata: withMetadata ? org.metadata : undefined,
        })),
        name: user.name,
        email: user.email,
        verifiedEmail: user.verifiedEmail,
      },
      { expiresIn: JWT_ACCESS_EXPIRES_IN },
    );

    return {
      name: user.name,
      email: user.email,
      userId: user.id,
      verifiedEmail: user.verifiedEmail,
      phone: user.phone,
      document: user.document,
      token: newToken,
      refreshToken: newRefreshToken,
      accesses: organizationsWithRoles,
    };
  }
}
