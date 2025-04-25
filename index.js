import express from 'express'
import dotenv from "dotenv"
import cookieParser from 'cookie-parser'
import cors from 'cors'

// custom routes
import userRouter from './routes/auth.routes.js'

dotenv.config()
const port= process.env.PORT || 4000
const app= express()

app.use(cookieParser())
app.use(cors({
    origin: 'http://localhost:5173'
}))

app.use(express.json())
app.use(express.urlencoded({extended: true}))


app.get("/", (req, res) =>{
    res.status(200).json({
        success: true,
        message: "test checked"
    })

})

app.use('/api/vi/users', userRouter)

app.listen(port, () =>{
    console.log(`backend is listening at port: ${port}`)
})