// backend/server.js - VERSION JWT COMPLÈTE (SANS SESSIONS)
require('dotenv').config();
const express = require('express');
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
const categoriesRoutes = require('./routes/categories');
const dishesRoutes = require('./routes/dishes');
const favoritesRoutes = require('./routes/favorites');

const app = express();
const PORT = process.env.PORT || 5000;

// ⚠️ CRITIQUE : Trust proxy pour Render
app.set('trust proxy', 1);

// ============================================
// CONFIGURATION CORS - VERSION JWT
// ============================================
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : ['http://localhost:3000'];

// Patterns pour Vercel et localhost
const allowedPatterns = [
  /^https:\/\/restaurant-test-frontend.*\.vercel\.app$/,
  /^http:\/\/localhost:\d+$/,
  /^http:\/\/127\.0\.0\.1:\d+$/,
];

console.log('🌍 CORS - Origines autorisées:', allowedOrigins);
console.log('🔍 CORS - Patterns autorisés:', allowedPatterns.map(p => p.toString()));

app.use(cors({
  origin: function (origin, callback) {
    console.log('🔍 CORS - Origin reçue:', origin);
    
    // Autoriser requêtes sans origin (Postman, mobile apps)
    if (!origin) {
      console.log('✅ CORS - Requête sans origin autorisée');
      return callback(null, true);
    }
    
    // Vérifier origines fixes
    if (allowedOrigins.includes(origin)) {
      console.log('✅ CORS - Origin autorisée (fixe):', origin);
      return callback(null, true);
    }
    
    // Vérifier patterns
    const matchesPattern = allowedPatterns.some(pattern => pattern.test(origin));
    if (matchesPattern) {
      console.log('✅ CORS - Origin autorisée (pattern):', origin);
      return callback(null, true);
    }
    
    console.log('❌ CORS - Origin refusée:', origin);
    return callback(null, false);
  },
  credentials: true, // Permet l'envoi du header Authorization
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  exposedHeaders: ['Authorization'],
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Gérer OPTIONS explicitement
app.options('*', (req, res) => {
  const origin = req.headers.origin;
  if (!origin || allowedOrigins.includes(origin) || allowedPatterns.some(p => p.test(origin))) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept');
    res.header('Access-Control-Allow-Credentials', 'true');
  }
  res.sendStatus(204);
});

// ============================================
// POSTGRESQL POOL
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

initPool(pool);
app.locals.pool = pool;

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Erreur connexion DB:', err.message);
  } else {
    console.log('✅ Connecté à Supabase PostgreSQL');
    release();
  }
});

pool.on('error', (err) => {
  console.error('❌ Erreur pool PostgreSQL:', err);
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
  message: 'Trop de requêtes',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: 'Trop de tentatives de connexion'
});

// ============================================
// BODY PARSER
// ============================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ============================================
// MIDDLEWARE DE LOGGING JWT
// ============================================
app.use((req, res, next) => {
  const timestamp = new Date().toISOString().substring(11, 19);
  
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  console.log('  📍 Origin:', req.headers.origin || 'none');
  console.log('  🔑 Authorization:', req.headers.authorization ? 'Bearer ***' : 'none');
  
  next();
});

// ============================================
// ROUTES
// ============================================

app.get('/', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'API Restaurant - JWT Auth',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    auth: 'JWT',
    version: '2.0.0'
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    auth: 'JWT',
    database: 'connected'
  });
});

// Test JWT (protégé)
app.get('/test-jwt', require('./middleware/auths').requireAuth, (req, res) => {
  res.json({
    message: 'JWT valide',
    user: {
      id: req.userId,
      email: req.userEmail,
      role: req.userRole
    }
  });
});

// Routes principales
app.use('/auth', authLimiter, authRoutes);
app.use('/settings', settingsRoutes);
app.use('/users', userRoutes);
app.use('/reservations', reservationRoutes);
app.use('/menus', menusRoutes);
app.use('/dashboard', dashboardRoutes);
app.use('/categories', categoriesRoutes);
app.use('/dishes', dishesRoutes);
app.use('/favorites', favoritesRoutes);

// ============================================
// GESTION ERREURS 404
// ============================================
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Route non trouvée',
    path: req.path,
    method: req.method
  });
});

// ============================================
// GESTION ERREURS GLOBALE
// ============================================
app.use((err, req, res, next) => {
  console.error('❌ Erreur serveur:', err);
  console.error('Stack:', err.stack);
  
  const isProduction = process.env.NODE_ENV === 'production';
  const errorMessage = isProduction 
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
// DÉMARRAGE SERVEUR
// ============================================
const server = app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════╗');
  console.log(`║  🚀 Serveur démarré (JWT MODE)       ║`);
  console.log(`║  📍 Port: ${PORT}                      ║`);
  console.log(`║  🌍 Environment: ${(process.env.NODE_ENV || 'development').padEnd(17)}║`);
  console.log(`║  🔐 Auth: JWT Tokens                 ║`);
  console.log('╚══════════════════════════════════════╝');
  console.log('');
});

// ============================================
// ARRÊT GRACIEUX
// ============================================
const gracefulShutdown = () => {
  console.log('\n⏳ Arrêt du serveur...');
  
  server.close(() => {
    console.log('✅ Serveur HTTP fermé');
    
    pool.end(() => {
      console.log('✅ Pool DB fermé');
      process.exit(0);
    });
  });
  
  setTimeout(() => {
    console.error('⚠️ Arrêt forcé');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  gracefulShutdown();
});

module.exports = app;