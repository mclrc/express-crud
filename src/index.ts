import { default as express, Request, Response } from 'express'
import { expressjwt as jwt } from 'express-jwt'
import cors from 'cors'
import userRouter from './api/user'
import postRouter from './api/post'
import prisma from './dbclient'

const app = express()

app.use(cors())
app.use(express.json())
app.use(logger)
app.use(jwt({
	secret: process.env['ACCESS_TOKEN_SECRET'] as string,
	algorithms: ['HS256'],
	credentialsRequired: false,
}))
app.use('/user', userRouter)
app.use('/post', postRouter)

function logger(req: Request, _res: Response, next: Function) {
	console.log(`[${req.method}] ${req.originalUrl}`)
	next()
}

async function main() {
	app.listen(3000)
}

main().then(async () => {
	await prisma.$disconnect()
}).catch(async e => {
	console.error(e)
	await prisma.$disconnect()
	process.exit(1)
})

export default app
