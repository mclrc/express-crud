import { Request, Response } from 'express'
import { validationResult } from 'express-validator'
import { Request as JwtRequest } from 'express-jwt'
import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import prisma from './dbclient'

const refreshTokens = new Map()

export function sha256(payload: string): string {
	return crypto.createHash('sha256').update(payload).digest('hex')
}

interface UserQuery {
	name?: string
	email?: string
}
export async function verifyPassword(userquery: UserQuery, password: string) {
	const hash = sha256(password)

	const user = await prisma.user.findUnique({
		where: userquery
	})

	return user && user.password == hash
}

export function createAccessToken(username: string, expiresIn: string): string {
	const token = jwt.sign({ username }, process.env['ACCESS_TOKEN_SECRET'] as string, { expiresIn })
	return token
}

export function createRefreshToken(username: string): string {
	const token = jwt.sign({ username }, process.env['REFRESH_TOKEN_SECRET'] as string)
	refreshTokens.set(username, token)
	return token
}

export function tryRefreshAccessToken(token: string, expiresIn: string): string | null {
	const { username } = jwt.verify(token, process.env['REFRESH_TOKEN_SECRET'] as any) as any
	if (refreshTokens.get(username) != token) {
		console.log(refreshTokens.get(username), token)
		console.log(refreshTokens)
		return null
	}
	return createAccessToken(username, expiresIn)
}

export function requireValidation(req: Request, res: Response, next: Function) {
	const errors = validationResult(req)
	console.log(req.body)

	if (!errors.isEmpty()) {
		return res.status(400).json({
			errors: errors.array(),
		})
	}

	next()
}

export function requireLogin(req: JwtRequest, res: Response, next: Function) {
	if (!req.auth?.['username']) {
		return res.status(401).json({
			message: 'Login required',
		})
	}
	next()
}

