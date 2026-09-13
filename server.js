const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: { origin: "*" }
});

// 미들웨어
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// 환경변수
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/rpg-game';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';
const PORT = process.env.PORT || 5000;

// ==================== 데이터베이스 연결 ====================
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB 연결 성공'))
  .catch(err => console.error('MongoDB 연결 실패:', err));

// ==================== 스키마 정의 ====================

// 사용자 스키마 (계정)
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  username: { type: String, unique: true, required: true },
  createdAt: { type: Date, default: Date.now }
});

// 플레이어 데이터 스키마 (게임 진행 상황)
const playerSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  playerName: { type: String, required: true },
  level: { type: Number, default: 1 },
  exp: { type: Number, default: 0 },
  hp: { type: Number, default: 100 },
  maxHp: { type: Number, default: 100 },
  gold: { type: Number, default: 0 },
  x: { type: Number, default: 2500 },
  y: { type: Number, default: 2500 },
  currentZone: { type: String, default: 'town' },
  equipment: { type: Object, default: {} },
  inventory: { type: Array, default: [] },
  skills: { type: Array, default: [] },
  stats: {
    strength: { type: Number, default: 5 },
    defense: { type: Number, default: 3 },
    attack: { type: Number, default: 10 }
  },
  lastSaved: { type: Date, default: Date.now },
  isOnline: { type: Boolean, default: false },
  socketId: String
});

const User = mongoose.model('User', userSchema);
const Player = mongoose.model('Player', playerSchema);

// ==================== 인증 미들웨어 ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: '토큰 없음' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: '토큰 검증 실패' });
    req.user = user;
    next();
  });
};

// ==================== API 엔드포인트 ====================

// 1. 회원가입
app.post('/api/signup', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    
    if (!email || !username || !password) {
      return res.status(400).json({ error: '모든 필드 입력 필요' });
    }
    
    // 이미 존재하는 사용자 확인
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: '이미 존재하는 이메일/닉네임' });
    }
    
    // 비밀번호 해시
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 새 사용자 생성
    const user = new User({
      email,
      username,
      password: hashedPassword
    });
    
    await user.save();
    
    // JWT 토큰 생성
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ 
      message: '회원가입 성공',
      token,
      userId: user._id,
      username: user.username
    });
  } catch (error) {
    console.error('회원가입 오류:', error);
    res.status(500).json({ error: '서버 오류' });
  }
});

// 2. 로그인
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: '이메일과 비밀번호 필수' });
    }
    
    // 사용자 찾기
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: '사용자 없음' });
    }
    
    // 비밀번호 확인
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: '비밀번호 오류' });
    }
    
    // JWT 토큰 생성
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ 
      message: '로그인 성공',
      token,
      userId: user._id,
      username: user.username
    });
  } catch (error) {
    console.error('로그인 오류:', error);
    res.status(500).json({ error: '서버 오류' });
  }
});

// 3. 플레이어 데이터 로드
app.get('/api/player/:playerId', authenticateToken, async (req, res) => {
  try {
    const player = await Player.findById(req.params.playerId);
    if (!player) {
      return res.status(404).json({ error: '플레이어 없음' });
    }
    res.json(player);
  } catch (error) {
    res.status(500).json({ error: '서버 오류' });
  }
});

// 4. 플레이어 생성 (새 게임)
app.post('/api/player', authenticateToken, async (req, res) => {
  try {
    const { playerName } = req.body;
    
    if (!playerName) {
      return res.status(400).json({ error: '플레이어 이름 필수' });
    }
    
    const player = new Player({
      userId: req.user.id,
      playerName,
      level: 1,
      exp: 0,
      hp: 100,
      maxHp: 100,
      gold: 0,
      x: 2500,
      y: 2500,
      currentZone: 'town'
    });
    
    await player.save();
    
    res.json({ 
      message: '플레이어 생성 성공',
      playerId: player._id,
      player
    });
  } catch (error) {
    console.error('플레이어 생성 오류:', error);
    res.status(500).json({ error: '서버 오류' });
  }
});

// 5. 플레이어 데이터 저장
app.put('/api/player/:playerId', authenticateToken, async (req, res) => {
  try {
    const { level, exp, hp, maxHp, gold, x, y, currentZone, inventory, equipment, stats } = req.body;
    
    const player = await Player.findByIdAndUpdate(
      req.params.playerId,
      {
        level,
        exp,
        hp,
        maxHp,
        gold,
        x,
        y,
        currentZone,
        inventory,
        equipment,
        stats,
        lastSaved: new Date()
      },
      { new: true }
    );
    
    res.json({ message: '저장 성공', player });
  } catch (error) {
    console.error('저장 오류:', error);
    res.status(500).json({ error: '서버 오류' });
  }
});

// 6. 사용자의 모든 플레이어 목록
app.get('/api/players', authenticateToken, async (req, res) => {
  try {
    const players = await Player.find({ userId: req.user.id });
    res.json(players);
  } catch (error) {
    res.status(500).json({ error: '서버 오류' });
  }
});

// ==================== WebSocket (실시간 멀티플레이) ====================

const onlinePlayers = {}; // 온라인 플레이어 저장

io.on('connection', (socket) => {
  console.log(`플레이어 연결: ${socket.id}`);
  
  // 플레이어 위치 업데이트
  socket.on('playerMove', (data) => {
    onlinePlayers[socket.id] = data;
    socket.broadcast.emit('playerUpdated', { socketId: socket.id, ...data });
  });
  
  // 플레이어 공격
  socket.on('playerAttack', (data) => {
    socket.broadcast.emit('playerAttackNotify', { socketId: socket.id, ...data });
  });
  
  // 플레이어 채팅
  socket.on('chat', (message) => {
    io.emit('chatMessage', { socketId: socket.id, message, timestamp: new Date() });
  });
  
  // 연결 해제
  socket.on('disconnect', () => {
    delete onlinePlayers[socket.id];
    io.emit('playerDisconnected', socket.id);
    console.log(`플레이어 연결 해제: ${socket.id}`);
  });
});

// ==================== 서버 시작 ====================

server.listen(PORT, () => {
  console.log(`🎮 게임 서버 실행 중: http://localhost:${PORT}`);
});
