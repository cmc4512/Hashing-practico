import { Controller, Post, Body } from '@nestjs/common';
import { HashingService } from './hashing.service';
import { EncryptionService } from './encryption.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly hashingService: HashingService,
    private readonly encryptionService: EncryptionService,
  ) {}

  @Post('hash')
  async hashPassword(@Body() body: { password: string }) {
    const hashedPassword = await this.hashingService.hashPassword(body.password);
    return { hashedPassword };
  }

  @Post('compare')
  async comparePasswords(@Body() body: { password: string; hashedPassword: string }) {
    const { password, hashedPassword } = body;
    const isMatch = await this.hashingService.comparePasswords(password, hashedPassword);
    return { isMatch };
  }

  @Post('encrypt')
  async encryptText(@Body() body: { text: string }) {
    const encryptedText = this.encryptionService.encrypt(body.text);
    return { encryptedText };
  }

  @Post('decrypt')
  async decryptText(@Body() body: { encryptedText: string }) {
    const decryptedText = this.encryptionService.decrypt(body.encryptedText);
    return { decryptedText };
  }
}
