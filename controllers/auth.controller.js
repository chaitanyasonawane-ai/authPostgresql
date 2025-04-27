import { PrismaClient } from "@prisma/client"
import bcrypt from "bcryptjs"
import crypto from "crypto"
import jwt from "jsonwebtoken"

const prisma = new PrismaClient()

export const registerUser = async (req, res) =>{
    const {name, email, password, phone}= req.body

    if(!name || !email || !password || !phone){
        console.log("data is missing")
        return res.status(400).json({
            message: "all fields are required"
        })
    }

    try {
        const existingUser= await prisma.user.findUnique({
            where: {email}
        })

        if (existingUser){
            return res.status(400).json({
                success: false,
                message: "user already exist"
            })
        }

        // hash the pass
        const hashPassword= await bcrypt.hash(password,10)
        const verificationToken= crypto.randomBytes(32).toString("hex")

        await prisma.user.create({
            data:{
                name,
                email,
                phone,
                password: hashPassword,
                verificationToken

            }
        })

        // send mail


    } catch (error) {
        return res.status(500).json({
            success: false,
            error,
            message: "registration failed"
        })
        
    }
}

export const loginUser = async(req, res) =>{
    const {email, password} = req.body

    if(!email || !password){
        return res.status(400).json({
            success: false,
            message: "all fields are required"
        })
    }


    try {
        const user = await prisma.user.findUnique({
            where: {email}
        })

        if(!user){
            return res.status(400).json({
                success: false,
                message: "invalid email or password"
            })
        }

        const isMatch = bcrypt.compare(password, user.password)

        if(!isMatch){
            return res.status(400).json({
                success: false,
                message: "invalid email or password"
            })
        }

        const token = jwt.sign(
            {
                id: user.id,
                role: user.role
            },
            process.env.JWT_SECRET,
            {expiresIn: '24h'}

        )

        const cookieOptions= {
            httpOnly: true
        }
        res.cookie('token', token, cookieOptions)

        return res.status(201).json({
            success: true,
            token,
            user:{
                id :user.id,
                name: user.email,
                email: user.email
            },
            message: "invalid email or password"
        })


        
    } catch (error) {
        return res.status(400).json({
            success: false,
            message: "login failed"
        })
    }
}