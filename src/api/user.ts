import { default as express } from 'express'
import { body } from 'express-validator'
import rateLimit from 'express-rate-limit'
import { Prisma } from '@prisma/client'
import prisma from '../dbclient'
import {
	sha256, verifyPassword, createAccessToken, createRefreshToken,
	tryRefreshAccessToken, requireValidation,
} from '../helpers'


const userRouter = express.Router()

const ratelimiter = rateLimit({
	windowMs: 60 * 1000,
	max: 5,
	standardHeaders: true,
})
userRouter.use(ratelimiter)

userRouter.post('/',
	body('email').isEmail(),
	body('password').isLength({
		min: 8,
		max: 64,
	}),
	body('username').isLength({
		min: 4,
		max: 20,
	}),
	requireValidation,
	async (req, res) => {
		try {
			const user = await prisma.user.create({
				data: {
					name: req.body.username as string,
					email: req.body.email as string,
					password: sha256(req.body.password),
				}
			})
			return res.status(200).json({
				token: createAccessToken(user.name, '30min'),
				refreshToken: createRefreshToken(user.name),
			})
		} catch (e) {
			if (e instanceof Prisma.PrismaClientKnownRequestError) {
				if (e.code === 'P2002') {
					return res.status(400).json({
						message: `A user with this ${e.meta?.target} already exists`
					})
				}
			}
		}
	}
)

userRouter.delete('/',
	body('username').exists(),
	body('password').exists(),
	requireValidation,
	async (req, res) => {
		if (await verifyPassword({ name: req.body.username }, req.body.password)) {
			try {
				await prisma.user.delete({
					where: {
						name: req.body.username,
					}
				})
				return res.status(200).json({
					message: 'User deleted successfully',
				})
			} catch (e) {
				return res.status(500).json({
					message: 'Cannot delete user',
				})
			}
		}
		return res.status(401).json({
			message: 'Invalid password and/or username',
		})
	}
)

userRouter.post('/login',
	body('username').exists(),
	body('password').exists(),
	requireValidation,
	async (req, res) => {
		if (await verifyPassword({ name: req.body.username }, req.body.password)) {
		   return res.status(200).json({
			   token: createAccessToken(req.body.username, '30min'),
			   refreshToken: createRefreshToken(req.body.username),
		   })
	   }
	   res.status(401).json({
		   message: 'Invalid password and/or username',
	   })
	}
)

userRouter.post('/refresh',
	body('refreshToken').exists(),
	requireValidation,
	async (req, res) => {
		try {
		   const refreshedAccessToken = tryRefreshAccessToken(req.body.refreshToken, '30min')
		   if (!refreshedAccessToken) {
			   return res.status(401).json({
				   message: 'Invalid refresh token',
			   })
		   }
		   res.status(200).json({
			   token: refreshedAccessToken,
		   })
		} catch (e) {
		   res.status(401).json({
			   message: 'Invalid or expired refresh token',
		   })
		}
	}
)

userRouter.get('/:id', async (req, res) => {
	const id = parseInt(req.params.id)
	if (isNaN(id)) {
		return res.status(400).json({
			message: 'Invalid user id'
		})
	}
	const user = await prisma.user.findUnique({
		where: {
			id,
		}
	})
	if (!user) {
		return res.status(404).json({
			message: 'User does not exist',
		})
	}
	res.status(200).json({
		id: user.id,
		name: user.name,
		email: user.email,
	})
})

export default userRouter
