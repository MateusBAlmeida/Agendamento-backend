import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import dotenv from 'dotenv';
import { body, validationResult } from 'express-validator';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import cors from 'cors';

dotenv.config();

const app = express();
app.use(express.json());


app.use(cors({
  origin: 'http://localhost:3000'
}));

const JWT_SECRET = process.env.JWT_SECRET || 'sua_chave_secreta';

// Conexão com SQLite
const dbPromise = open({
  filename: './db.sqlite',
  driver: sqlite3.Database
});

// Cria tabelas
(async () => {
  const db = await dbPromise;
  await db.exec(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT,
      email TEXT UNIQUE,
      senha_hash TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reservas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER,
      tipo TEXT, -- 'sala' ou 'carro'
      item_nome TEXT,
      data_inicio TEXT,
      data_fim TEXT
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL,
      expires_at DATETIME NOT NULL,
      FOREIGN KEY (user_id) REFERENCES usuarios(id)
    );
  `);
})();

// Middleware de validação para registro
const validateRegister = [
  body('email').isEmail().normalizeEmail().withMessage('Email inválido'),
  body('senha').isLength({ min: 6 }).withMessage('Senha deve ter no mínimo 6 caracteres'),
  body('nome').trim().not().isEmpty().withMessage('Nome é obrigatório')
];

// Registro
app.post('/register', validateRegister, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { nome, email, senha } = req.body;
  const db = await dbPromise;

  try {
    // Verifica se email já existe
    const existingUser = await db.get('SELECT id FROM usuarios WHERE email = ?', [email]);
    if (existingUser) {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }

    const senhaHash = await bcrypt.hash(senha, 10);
    
    await db.run(
      'INSERT INTO usuarios (nome, email, senha_hash) VALUES (?, ?, ?)',
      [nome, email, senhaHash]
    );
    
    res.status(201).json({ message: 'Usuário cadastrado com sucesso' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rate limiting para previnir força bruta
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // limite de 5 tentativas
  message: { error: 'Muitas tentativas de login. Tente novamente mais tarde.' }
});

// Login
app.post('/login', loginLimiter, async (req, res) => {
  const { email, senha } = req.body;
  const db = await dbPromise;

  try {
    const user = await db.get('SELECT * FROM usuarios WHERE email = ?', [email]);

    if (!user) {
      console.log(`Tentativa de login com email não cadastrado: ${email}`);
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const valid = await bcrypt.compare(senha, user.senha_hash);

    if (!valid) {
      console.log(`Senha incorreta para o usuário: ${email}`);
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Gera access token
    const token = jwt.sign(
      { 
        id: user.id, 
        nome: user.nome,
        email: user.email
      }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    // Gera refresh token
    const refreshToken = crypto.randomBytes(40).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // expira em 30 dias

    await db.run(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
      [user.id, refreshToken, expiresAt.toISOString()]
    );

    // Remove senha do objeto retornado
    delete user.senha_hash;
    
    res.json({ 
      user,
      token,
      refreshToken,
      expiresIn: 86400 // 24h em segundos
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para refresh token
app.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  
  try {
    const db = await dbPromise;
    const tokenData = await db.get(
      'SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > datetime("now")',
      [refreshToken]
    );

    if (!tokenData) {
      return res.status(401).json({ error: 'Token inválido ou expirado' });
    }

    const user = await db.get('SELECT * FROM usuarios WHERE id = ?', [tokenData.user_id]);
    
    // Gera novo access token
    const newAccessToken = jwt.sign(
      { id: user.id, nome: user.nome, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ 
      token: newAccessToken,
      expiresIn: 86400 // 24h em segundos
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Middleware auth
const auth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token não enviado.' });

  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido.' });
  }
};

// Fazer reserva
app.post('/reservas', auth, async (req, res) => {
  const { tipo, item_nome, data_inicio, data_fim } = req.body;
  const db = await dbPromise;

  // Você pode validar conflitos aqui!

  await db.run(
    'INSERT INTO reservas (usuario_id, tipo, item_nome, data_inicio, data_fim) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, tipo, item_nome, data_inicio, data_fim]
  );

  res.json({ message: 'Reserva criada.' });
});

// Listar reservas do usuário
app.get('/reservas', auth, async (req, res) => {
  const db = await dbPromise;
  const reservas = await db.all('SELECT * FROM reservas WHERE usuario_id = ?', [req.user.id]);
  res.json(reservas);
});

// Listar todas as reservas com filtros
app.get('/reservas/calendario', auth, async (req, res) => {
  const { tipo, item_nome, data_inicio, data_fim } = req.query;
  const db = await dbPromise;
  
  let query = 'SELECT r.*, u.nome as usuario_nome FROM reservas r LEFT JOIN usuarios u ON r.usuario_id = u.id WHERE 1=1';
  const params = [];

  if (tipo) {
    query += ' AND r.tipo = ?';
    params.push(tipo);
  }

  if (item_nome) {
    query += ' AND r.item_nome = ?';
    params.push(item_nome);
  }

  if (data_inicio) {
    query += ' AND r.data_fim > ?';
    params.push(data_inicio);
  }

  if (data_fim) {
    query += ' AND r.data_inicio < ?';
    params.push(data_fim);
  }

  try {
    const reservas = await db.all(query, params);
    res.json(reservas);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao buscar reservas' });
  }
});

app.listen(3001, () => {
  console.log('Backend rodando em http://localhost:3001');
});
