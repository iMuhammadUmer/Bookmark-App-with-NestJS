import { Controller } from '@nestjs/common';
import { Get } from '@nestjs/common/decorators/http/request-mapping.decorator';

@Controller('users')
export class UserController {
  @Get('me')
  getMe() {
    return 'user info';
  }
}
