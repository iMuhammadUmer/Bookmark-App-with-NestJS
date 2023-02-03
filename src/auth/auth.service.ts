import { PrismaService } from '../prisma/prisma.service';
import { Injectable } from '@nestjs/common';
import { AuthDto } from '../dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    // generate password hash
    const hash = await argon.hash(dto.password);

    // save new user in db
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        password: hash,
      },
      select: {
        // use select: {} to display desired keys if success
        id: true,
        email: true,
      },
    });
    // return saved user
    return user;
  }
  signin() {
    return 'User signed in';
  }
}
