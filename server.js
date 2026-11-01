const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const app = express();
const db = new Database('comunicados.db');

const SETORES = ['Corte', 'Separação de Corte', 'Bordado', 'Estampa', 'Costura', 'Finalização', 'Administrativo', 'Compras'];
const STATUS = ['Novo', 'Em andamento', 'Concluído'];

db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    login TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL,
    setor TEXT NOT NULL,
    admin INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS recados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titulo TEXT NOT NULL,
    texto TEXT NOT NULL,
    setor TEXT NOT NULL,
    status TEXT DEFAULT 'Novo',
    autor_id INTEGER NOT NULL,
    criado_em TEXT DEFAULT (datetime('now','localtime'))
  );
`);

if (!db.prepare('SELECT 1 FROM usuarios WHERE login = ?').get('admin')) {
  db.prepare('INSERT INTO usuarios (nome, login, senha, setor, admin) VALUES (?,?,?,?,1)')
    .run('Administrador', 'admin', bcrypt.hashSync('admin123', 10), 'Corte');
}

app.use(express.json());
app.use(session({
  secret: 'troque-este-segredo-por-um-texto-grande-e-aleatorio',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 12 }
}));
app.use(express.static('public'));

const logado = (req, res, next) => req.session.user ? next() : res.status(401).json({ erro: 'Não logado' });
const soAdmin = (req, res, next) => req.session.user && req.session.user.admin ? next() : res.status(403).json({ erro: 'Só administrador' });

app.post('/api/login', (req, res) => {
  const { login, senha } = req.body;
  const u = db.prepare('SELECT * FROM usuarios WHERE login = ?').get(login);
  if (!u || !bcrypt.compareSync(senha || '', u.senha)) return res.status(401).json({ erro: 'Login ou senha incorretos' });
  req.session.user = { id: u.id, nome: u.nome, login: u.login, setor: u.setor, admin: u.admin };
  res.json(req.session.user);
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/eu', logado, (req, res) => res.json(req.session.user));
app.get('/api/setores', logado, (req, res) => res.json({ setores: SETORES, status: STATUS }));

app.get('/api/recados', logado, (req, res) => {
  const lista = db.prepare(`
    SELECT r.*, u.nome AS autor_nome, u.setor AS autor_setor
    FROM recados r JOIN usuarios u ON u.id = r.autor_id
    ORDER BY r.id DESC
  `).all();
  res.json(lista);
});

app.post('/api/recados', logado, (req, res) => {
  const { titulo, texto, setor } = req.body;
  if (!titulo || !texto || !SETORES.includes(setor)) return res.status(400).json({ erro: 'Dados inválidos' });
  db.prepare('INSERT INTO recados (titulo, texto, setor, autor_id) VALUES (?,?,?,?)')
    .run(titulo.trim(), texto.trim(), setor, req.session.user.id);
  res.json({ ok: true });
});

app.patch('/api/recados/:id/status', logado, (req, res) => {
  const { status } = req.body;
  if (!STATUS.includes(status)) return res.status(400).json({ erro: 'Status inválido' });
  db.prepare('UPDATE recados SET status = ? WHERE id = ?').run(status, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/recados/:id', logado, (req, res) => {
  const r = db.prepare('SELECT autor_id FROM recados WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ erro: 'Não encontrado' });
  if (r.autor_id !== req.session.user.id && !req.session.user.admin) return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('DELETE FROM recados WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/usuarios', soAdmin, (req, res) => {
  res.json(db.prepare('SELECT id, nome, login, setor, admin FROM usuarios ORDER BY nome').all());
});

app.post('/api/usuarios', soAdmin, (req, res) => {
  const { nome, login, senha, setor } = req.body;
  if (!nome || !login || !senha || !SETORES.includes(setor)) return res.status(400).json({ erro: 'Dados inválidos' });
  try {
    db.prepare('INSERT INTO usuarios (nome, login, senha, setor) VALUES (?,?,?,?)')
      .run(nome.trim(), login.trim(), bcrypt.hashSync(senha, 10), setor);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ erro: 'Esse login já existe' });
  }
});

app.patch('/api/usuarios/:id/senha', soAdmin, (req, res) => {
  if (!req.body.senha) return res.status(400).json({ erro: 'Senha vazia' });
  db.prepare('UPDATE usuarios SET senha = ? WHERE id = ?').run(bcrypt.hashSync(req.body.senha, 10), req.params.id);
  res.json({ ok: true });
});

app.delete('/api/usuarios/:id', soAdmin, (req, res) => {
  if (Number(req.params.id) === req.session.user.id) return res.status(400).json({ erro: 'Você não pode apagar a si mesmo' });
  db.prepare('DELETE FROM usuarios WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.listen(3000, () => console.log('Rodando em http://localhost:3000'));