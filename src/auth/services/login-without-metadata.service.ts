import * as bcrypt from 'bcrypt';

import { JwtService } from '@nestjs/jwt';
import { LoginUserDto } from '../dto/login-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from '../database/providers/schema/user.schema';
import { Model } from 'mongoose';
import { Inject, NotFoundException } from '@nestjs/common';
import { RefreshTokenService } from './refresh-token.service';

export class LoginWithoutMetadataService {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<User>,
    @Inject('jwt-service') private readonly jwtService: JwtService,
    private readonly refreshTokenService: RefreshTokenService,
  ) {}

  async execute(data: LoginUserDto) {
    const identifiers = ['email', 'document', 'phone'] as const;

    const providedIdentifier = identifiers.find((key) => data[key]);

    if (!providedIdentifier) {
      throw new NotFoundException('No identifier provided');
    }

    const query = { [providedIdentifier]: data[providedIdentifier] };

    const user = await this.userModel.findOne(query);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const isPasswordValid = await bcrypt.compare(data.password, user.password);

    if (!isPasswordValid) {
      throw new NotFoundException('User not found');
    }

    const userId = user._id.toString();

    // Default do jwt-service (90d) — clientes legados não quebram.
    const token = this.jwtService.sign({
      sub: user._id,
      id: user._id,
      _id: user._id,
    });

    const refreshToken =
      await this.refreshTokenService.issueRefreshToken(userId);

    return {
      user: { [providedIdentifier]: user[providedIdentifier], id: user._id },
      token,
      refreshToken,
    };
  }
}
