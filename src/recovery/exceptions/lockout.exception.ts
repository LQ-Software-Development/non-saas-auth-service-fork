import { HttpException, HttpStatus } from '@nestjs/common';

export class LockoutException extends HttpException {
  constructor(message = 'Muitas tentativas. Tente novamente mais tarde.') {
    super(message, HttpStatus.TOO_MANY_REQUESTS);
  }
}
