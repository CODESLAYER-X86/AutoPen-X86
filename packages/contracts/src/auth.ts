/** Authentication & user contracts. */
import { z } from 'zod';
import { IsoDateTimeSchema } from './common.js';

export const RegisterRequestSchema = z
  .object({
    email: z.string().email().max(320),
    name: z.string().min(1).max(200),
    password: z.string().min(10, 'Password must be at least 10 characters').max(128),
  })
  .strict();
export type RegisterRequest = z.infer<typeof RegisterRequestSchema>;

export const LoginRequestSchema = z
  .object({
    email: z.string().email().max(320),
    password: z.string().min(1).max(128),
  })
  .strict();
export type LoginRequest = z.infer<typeof LoginRequestSchema>;

export const UserSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  name: z.string(),
  created_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
});
export type User = z.infer<typeof UserSchema>;

export const AuthSessionSchema = z.object({
  token: z.string(),
  expires_at: IsoDateTimeSchema,
  user: UserSchema,
});
export type AuthSession = z.infer<typeof AuthSessionSchema>;
