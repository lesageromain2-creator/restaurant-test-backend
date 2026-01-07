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
// MIDDLEWARE CORS
// ============================================
// Configuration CORS améliorée
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : ['http://localhost:3000', 'http://localhost:5173','https://restaurant-frontend-foni7k5of-devros-projects.vercel.app'];

console.log('🌍 Origines autorisées:', allowedOrigins);

const corsOptions = {
  origin: function (origin, callback) {
    // Autoriser les requêtes sans origin (Postman, mobile apps, etc.)
    if (!origin) {
      console.log('✅ Requête sans origin autorisée');
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin)) {
      console.log('✅ Origin autorisée:', origin);
      callback(null, true);
    } else {
      console.log('❌ Origin refusée:', origin);
      console.log('📋 Origines autorisées:', allowedOrigins);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  exposedHeaders: ['Set-Cookie'],
  preflightContinue: false,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

// Important : Gérer les requêtes OPTIONS explicitement
app.options('*', cors(corsOptions));
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
    createTableIfMissing: false
  }),
  secret: process.env.SESSION_SECRET || 'votre-secret-super-securise-changez-moi',
  resave: false,
  saveUninitialized: false,
  name: 'restaurant.sid', // Nom du cookie
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true en production (HTTPS)
    httpOnly: true, // Protection XSS
    maxAge: 24 * 60 * 60 * 1000, // 24 heures
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // Important pour cross-domain
  }
};




app.use(session({
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
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  },
  rolling: true
}));

// APRÈS LA CONFIGURATION DES SESSIONS, AJOUTER CE DEBUG
app.use((req, res, next) => {
  console.log('🔍 Session Debug:', {
    path: req.path,
    sessionID: req.sessionID,
    session: req.session,
    hasUserId: !!req.session?.userId,
    cookie: req.session?.cookie
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
// ROUTES
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Serveur opérationnel',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    session: req.session.userId ? 'active' : 'none'
  });
});

app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/users', userRoutes);
app.use('/api/reservations', reservationRoutes);
app.use('/api/menus', menusRoutes);
app.use('/api/dashboard', dashboardRoutes);

// ============================================
// GESTION DES ERREURS 404
// ============================================
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Route non trouvée',
    path: req.path 
  });
});

// ============================================
// MIDDLEWARE DE GESTION D'ERREURS GLOBAL
// ============================================
app.use((err, req, res, next) => {
  console.error('❌ Erreur serveur:', err.stack);
  
  const errorMessage = process.env.NODE_ENV === 'production' 
    ? 'Erreur serveur interne' 
    : err.message;
  
  res.status(err.status || 500).json({ 
    error: errorMessage,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
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


