import { Router } from "express";
//Importing the usersRouter and the productsRouter
import usersRouter from "./users.js"

const router = Router()

//Registry router and add the prefix /api
router.use("/api", usersRouter) //Registry usersRouter and add the prefix /api

export default router;