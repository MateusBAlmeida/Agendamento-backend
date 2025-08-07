import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcrypt';

async function seed() {
  const db = await open({
    filename: './db.sqlite',
    driver: sqlite3.Database
  });

  const usuarios = [
    { nome: 'Mateus Almeida', email: 'mateusalmeida@parademinas.mg.gov.br', senha: 'Kaz-2y5' },
    // { nome: 'Maria Silva', email: 'maria@empresa.com', senha: 'senha123' },
    // { nome: 'João Souza', email: 'joao@empresa.com', senha: 'abc123' }
  ];

  for (const u of usuarios) {
    const hash = await bcrypt.hash(u.senha, 10);
    try {
      await db.run(
        'INSERT INTO usuarios (nome, email, senha_hash) VALUES (?, ?, ?)',
        [u.nome, u.email, hash]
      );
      console.log(`✅ Usuário ${u.nome} inserido`);
    } catch (err) {
      console.error(`⚠️ Erro ao inserir ${u.email}:`, err.message);
    }
  }

  await db.close();
}

seed();
