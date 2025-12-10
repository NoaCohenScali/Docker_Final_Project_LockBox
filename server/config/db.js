const mysql = require("mysql2");

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "pmuser",
  password: process.env.DB_PASSWORD || "StrongPass123!",
  database: process.env.DB_NAME || "passwordmanager",
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});



module.exports = pool;
