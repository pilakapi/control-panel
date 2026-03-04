import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import axios from "axios";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set("view engine", "ejs");

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET;

/* =======================
   PANEL ADMIN
======================= */

app.get("/", async (req, res) => {
  const users = await pool.query("SELECT * FROM users ORDER BY id DESC");
  res.render("dashboard", { users: users.rows });
});

app.post("/create-user", async (req, res) => {
  const { username, password, max_connections, expiration_date } = req.body;
  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    "INSERT INTO users (username, password_hash, max_connections, expiration_date) VALUES ($1,$2,$3,$4)",
    [
      username,
      hash,
      max_connections || 1,
      expiration_date || null
    ]
  );

  res.redirect("/");
});

app.post("/reactivate/:id", async (req, res) => {
  const { expiration_date } = req.body;

  await pool.query(
    "UPDATE users SET active=true, expiration_date=$1 WHERE id=$2",
    [expiration_date || null, req.params.id]
  );

  res.redirect("/");
});

app.post("/toggle/:id", async (req, res) => {
  await pool.query(
    "UPDATE users SET active = NOT active WHERE id=$1",
    [req.params.id]
  );
  res.redirect("/");
});

app.post("/add-playlist/:id", async (req, res) => {
  const { source_url } = req.body;
  await pool.query(
    "INSERT INTO playlists (user_id, source_url) VALUES ($1,$2)",
    [req.params.id, source_url]
  );
  res.redirect("/");
});

/* =======================
   M3U PROTEGIDO
======================= */

app.get("/m3u/:username", async (req, res) => {
  const { username } = req.params;
  const ip = req.ip;

  const user = await pool.query(
    "SELECT * FROM users WHERE username=$1 AND active=true",
    [username]
  );

  if (user.rows.length === 0)
    return res.status(403).send("No autorizado");

  const u = user.rows[0];

  if (u.expiration_date && new Date() > u.expiration_date)
    return res.status(403).send("Cuenta expirada");

  const conn = await pool.query(
    "SELECT COUNT(*) FROM connections WHERE user_id=$1",
    [u.id]
  );

  if (conn.rows[0].count >= u.max_connections)
    return res.status(403).send("Limite alcanzado");

  await pool.query(
    "INSERT INTO connections (user_id, ip_address, last_seen) VALUES ($1,$2,NOW()) ON CONFLICT (user_id,ip_address) DO UPDATE SET last_seen=NOW()",
    [u.id, ip]
  );

  const playlist = await pool.query(
    "SELECT * FROM playlists WHERE user_id=$1",
    [u.id]
  );

  const source = await axios.get(playlist.rows[0].source_url);

  let modified = source.data.replace(
    /(http.*?\.m3u8)/g,
    (match) => {
      const token = jwt.sign(
        { url: match, user: u.id },
        JWT_SECRET,
        { expiresIn: "6h" }
      );
      return `${req.protocol}://${req.get("host")}/stream?token=${token}`;
    }
  );

  res.setHeader("Content-Type", "application/vnd.apple.mpegurl");
  res.send(modified);
});

/* =======================
   STREAM PROXY
======================= */

app.get("/stream", async (req, res) => {
  try {
    const decoded = jwt.verify(req.query.token, JWT_SECRET);

    const stream = await axios({
      method: "get",
      url: decoded.url,
      responseType: "stream"
    });

    stream.data.pipe(res);
  } catch {
    res.status(403).send("Stream invalido");
  }
});

app.listen(process.env.PORT || 3000);