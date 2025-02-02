// src/api/routes/auth.routes.ts
import express from 'express';
import { authController } from '@/api/controllers/auth.controller';

const router = express.Router();

router.post('/login', authController.login);
router.post('/logout', authController.logout);

export default router;