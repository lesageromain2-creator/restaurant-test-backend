// backend/server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { initPool } = require('./database/db');

// Import des routes
const authRoutes = require('./routes/auth');
const settingsRoutes = require('./routes/settings');
const userRoutes = require('./routes/users');
const reservationRoutes = require('./routes/reservations');
const menusRoutes = require('./routes/menus');
const dashboardRoutes = require('./routes/dashboard');

const app = express();
const PORT = process.env.PORT || 5000;

// Important: Trust proxy pour que Express reconnaisse les requêtes HTTPS derrière un reverse proxy
app.set('trust proxy', 1);

// ============================================
// CONFIGURATION CORS (DOIT ÊTRE EN PREMIER)
// ============================================
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : [
      'http://localhost:3000',
      'http://localhost:3001', 
      'http://localhost:5173',
    ];

// Patterns dynamiques pour Vercel et localhost
const allowedPatterns = [
  /^https:\/\/restaurant-frontend.*\.vercel\.app$/,  // Tous les preview deployments Vercel
  /^http:\/\/localhost:\d+$/,                        // Tous les ports localhost
  /^http:\/\/127\.0\.0\.1:\d+$/,                     // Localhost via IP
];

console.log('🌍 Origines fixes autorisées:', allowedOrigins);
console.log('🔍 Patterns dynamiques activés: Vercel wildcard + localhost');

app.use(cors({
  origin: function (origin, callback) {
    console.log('🔍 Origin reçue:', origin);
    
    // Autoriser les requêtes sans origin (Postman, mobile apps, etc.)
    if (!origin) {
      console.log('✅ Requête sans origin autorisée');
      return callback(null, true);
    }
    
    // Vérifier les origines fixes
    if (allowedOrigins.includes(origin)) {
      console.log('✅ Origin autorisée (fixe):', origin);
      return callback(null, true);
    }
    
    // Vérifier les patterns dynamiques
    const matchesPattern = allowedPatterns.some(pattern => pattern.test(origin));
    if (matchesPattern) {
      console.log('✅ Origin autorisée (pattern):', origin);
      return callback(null, true);
    }
    
    console.log('❌ Origin refusée:', origin);
    console.log('📋 Origines fixes disponibles:', allowedOrigins);
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  exposedHeaders: ['Set-Cookie'],
  maxAge: 86400
}));

// Gérer explicitement les requêtes OPTIONS (preflight)
app.options('*', (req, res) => {
  const origin = req.headers.origin;
  if (!origin || allowedOrigins.includes(origin) || allowedPatterns.some(pattern => pattern.test(origin))) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept');
    res.header('Access-Control-Allow-Credentials', 'true');
  }
  res.sendStatus(204);
});

// ============================================
// CONFIGURATION POSTGRESQL (SUPABASE)
// ============================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Initialiser le module database avec le pool
initPool(pool);

// Rendre le pool disponible dans toute l'application
app.locals.pool = pool;

// Test de connexion
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Erreur de connexion à la base:', err.message);
    console.error('Vérifiez votre DATABASE_URL dans le fichier .env');
  } else {
    console.log('✅ Connecté à Supabase PostgreSQL');
    release();
  }
});

// Gestion des erreurs du pool
pool.on('error', (err) => {
  console.error('❌ Erreur inattendue du pool PostgreSQL:', err);
});

// ============================================
// MIDDLEWARES DE SÉCURITÉ
// ============================================

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Trop de requêtes depuis cette IP, veuillez réessayer plus tard.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: 'Trop de tentatives de connexion, veuillez réessayer dans 15 minutes.'
});

// ============================================
// MIDDLEWARE BODY PARSER
// ============================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ============================================
// CONFIGURATION DES SESSIONS
// ============================================

const sessionConfig = {
  store: new pgSession({
    pool: pool,
    tableName: 'sessions',
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 heures
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS uniquement en production
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // 'none' pour cross-domain en production
    domain: process.env.NODE_ENV === 'production' ? undefined : undefined // Pas de domain spécifique
  },
  rolling: true,
  proxy: true // Important pour les reverse proxies (Render)
};

app.use(session(sessionConfig));

// Middleware de debug des sessions
app.use((req, res, next) => {
  console.log('🔍 Session Debug:', {
    path: req.path,
    method: req.method,
    origin: req.headers.origin,
    sessionID: req.sessionID,
    hasUserId: !!req.session?.userId,
    cookie: req.session?.cookie,
    isSecure: req.secure,
    protocol: req.protocol
  });
  next();
});

// ============================================
// MIDDLEWARE DE LOGGING
// ============================================
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
  if (req.session && req.session.userId) {
    console.log(`  └─ Session: userId=${req.session.userId}, role=${req.session.role}`);
  }
  next();
});

// ============================================
// ROUTES (SANS PRÉFIXE /api/)
// ============================================

app.get('/', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'API Restaurant - Serveur opérationnel',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    cors: 'Vercel wildcard + fixed origins enabled',
    session: {
      secure: sessionConfig.cookie.secure,
      sameSite: sessionConfig.cookie.sameSite,
      httpOnly: sessionConfig.cookie.httpOnly
    }
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Serveur opérationnel',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    session: req.session.userId ? 'active' : 'none',
    database: 'connected',
    cors: 'wildcard enabled'
  });
});

// Routes principales
app.use('/auth', authLimiter, authRoutes);
app.use('/settings', settingsRoutes);
app.use('/users', userRoutes);
app.use('/reservations', reservationRoutes);
app.use('/menus', menusRoutes);
app.use('/dashboard', dashboardRoutes);

// ============================================
// GESTION DES ERREURS 404
// ============================================
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Route non trouvée',
    path: req.path,
    method: req.method,
    availableRoutes: [
      'GET /',
      'GET /health',
      'POST /auth/login',
      'POST /auth/logout',
      'GET /auth/me',
      'GET /settings',
      'GET /users',
      'GET /reservations',
      'GET /menus',
      'GET /dashboard'
    ]
  });
});

// ============================================
// MIDDLEWARE DE GESTION D'ERREURS GLOBAL
// ============================================
app.use((err, req, res, next) => {
  console.error('❌ Erreur serveur:', err);
  console.error('Stack:', err.stack);
  
  const errorMessage = process.env.NODE_ENV === 'production' 
    ? 'Erreur serveur interne' 
    : err.message;
  
  res.status(err.status || 500).json({ 
    error: errorMessage,
    ...(process.env.NODE_ENV === 'development' && { 
      stack: err.stack,
      details: err.toString()
    })
  });
});

// ============================================
// DÉMARRAGE DU SERVEUR
// ============================================
const server = app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════╗');
  console.log(`║  🚀 Serveur démarré sur port ${PORT}   ║`);
  console.log(`║  🌍 Environment: ${process.env.NODE_ENV || 'development'}        ║`);
  console.log(`║  🔗 URL: http://localhost:${PORT}       ║`);
  console.log('╚══════════════════════════════════════╝');
  console.log('');
  console.log('🔒 CORS Configuration:');
  console.log('  ✅ Vercel wildcard enabled');
  console.log('  ✅ Localhost all ports enabled');
  console.log('  ✅ Fixed origins enabled');
  console.log('');
  console.log('🍪 Session Configuration:');
  console.log(`  ✅ Secure: ${sessionConfig.cookie.secure}`);
  console.log(`  ✅ SameSite: ${sessionConfig.cookie.sameSite}`);
  console.log(`  ✅ HttpOnly: ${sessionConfig.cookie.httpOnly}`);
  console.log(`  ✅ Proxy: ${sessionConfig.proxy}`);
  console.log('');
  console.log('📋 Routes disponibles:');
  console.log('  - GET  /');
  console.log('  - GET  /health');
  console.log('  - POST /auth/login');
  console.log('  - POST /auth/logout');
  console.log('  - GET  /auth/me');
  console.log('  - GET  /settings');
  console.log('  - *    /users');
  console.log('  - *    /reservations');
  console.log('  - *    /menus');
  console.log('  - *    /dashboard');
  console.log('');
});

// ============================================
// GESTION DE L'ARRÊT GRACIEUX
// ============================================
const gracefulShutdown = () => {
  console.log('\n⏳ Arrêt du serveur en cours...');
  
  server.close(() => {
    console.log('✅ Serveur HTTP fermé');
    
    pool.end(() => {
      console.log('✅ Pool de connexions fermé');
      process.exit(0);
    });
  });
  
  setTimeout(() => {
    console.error('⚠️ Arrêt forcé après timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  gracefulShutdown();
});

module.exports = app;