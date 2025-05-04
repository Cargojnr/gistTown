import { Sequelize } from 'sequelize';
import env from "dotenv"

env.config()

const sequelize = new Sequelize({
  dialect: 'postgres',
  username: process.env.DB_USERNAME, // Use environment variables
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  logging: false, // Disable logging for clean output
});

export default sequelize;