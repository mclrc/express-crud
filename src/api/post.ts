import { default as express } from 'express'
import { body } from 'express-validator'
import { Request as JwtRequest } from 'express-jwt'
import rateLimit from 'express-rate-limit'
import prisma from '../dbclient'
import { requireValidation, requireLogin } from '../helpers'

const postRouter = express.Router()

postRouter.post('/',
	rateLimit({
		windowMs: 60 * 1000,
		max: 3,
		standardHeaders: true,
	}),
	requireLogin,
	body('message').isLength({
		max: 256,
	}),
	requireValidation,
	async (req: JwtRequest, res) => {
		const user = await prisma.user.findUnique({
			where: {
				name: req.auth?.['username'] as string,
			}
		})
		if (!user) {
			return res.status(400).json({
				message: 'Invalid user',
			})
		}
		try {
			const post = await prisma.post.create({
				data: {
					authorId: user.id,
					message: req.body.message as string,
				}
			})
			return res.status(200).json(post)
		} catch(e) {
			return res.status(400).json({
				message: 'Cannot create post',
			})
		}
	}
)

postRouter.get('/:id', async (req, res) => {
	const id = parseInt(req.params.id)
	if (isNaN(id)) {
		return res.status(400).json({
			message: 'Invalid post id',
		})
	}
	const post = await prisma.post.findUnique({
		where: {
			id,
		}
	})
	if (!post) {
		return res.status(404).json({
			message: 'Post not found',
		})
	}
	return res.status(200).json(post)
})

postRouter.delete('/:id', requireLogin, async (req: JwtRequest, res) => {
	const user = await prisma.user.findUnique({
		where: {
			name: req.auth?.['username'] as string,
		}
	})
	if (!user) {
		return res.status(400).json({
			message: 'Invalid user',
		})
	}
	const post = await prisma.post.findUnique({
		where: {
			id: parseInt(req.params.id),
		}
	})
	if (!post || post.authorId != user.id) {
		return res.status(400).json({
			message: 'Cannot delete post',
		})
	}
	res.status(200).json({
		message: 'Post deleted successfully',
	})
})

export default postRouter
