const express = require('express');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const { createHash, randomBytes, randomUUID, scrypt, timingSafeEqual } = require('crypto');
const fsPromises = require('fs/promises');
const { promisify } = require('util');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
const multer = require('multer');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { createPaymentAdapter } = require('./payment-adapter');
const { isAssistantModelReady, requestShopAssistantAnswer } = require('./shop-assistant');
const { decryptKycDocument, detectKycDocumentMime, encryptKycDocument, getKycEncryptionKey } = require('./kyc-storage');
const app = express();
const kycStorageDirectory = process.env.KYC_STORAGE_DIR || path.join(__dirname, 'private', 'kyc');
const trustProxyHops = Number(process.env.TRUST_PROXY_HOPS || 0);
if (!Number.isInteger(trustProxyHops) || trustProxyHops < 0 || trustProxyHops > 5) {
  throw new Error('TRUST_PROXY_HOPS must be an integer between 0 and 5.');
}
app.set('trust proxy', trustProxyHops);
const scryptAsync = promisify(scrypt);
const sessionCookie = 'z_session';
const sessionDuration = 7 * 24 * 60 * 60 * 1000;
const paymentAdapter = createPaymentAdapter(process.env.PAYMENT_MODE || 'mock');
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Try again in 15 minutes.' }
});
const supportRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'You have sent several support requests. Try again in an hour.' }
});
const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many password reset attempts. Try again in an hour.' }
});
const sellerUploadRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many image uploads. Try again in an hour.' }
});
const shopAssistantRateLimit = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'You have asked several questions. Try again in a few minutes.' }
});
const kycSubmissionRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many verification submissions. Try again later.' }
});
const imageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1, fields: 1, fieldSize: 32 },
  fileFilter: (req, file, callback) => callback(null, ['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype))
});
const kycDocumentUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1, fields: 2, fieldSize: 256 },
  fileFilter: (req, file, callback) => callback(null, ['application/pdf', 'image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype))
});
const passwordResetMailer = process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASSWORD
  ? nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true',
    requireTLS: process.env.SMTP_SECURE !== 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
  })
  : null;
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
  salt: { type: String, required: true },
  passwordHash: { type: String, required: true }
}, { timestamps: true });
const sessionSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt: { type: Date, required: true, expires: 0 }
}, { timestamps: true });
const passwordResetSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  expiresAt: { type: Date, required: true, expires: 0 }
}, { timestamps: true });
const shopSchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  name: { type: String, required: true, trim: true, maxlength: 80 },
  slug: { type: String, required: true, unique: true },
  description: { type: String, required: true, trim: true, maxlength: 500 },
  coverImageUrl: { type: String, default: '' },
  town: { type: String, required: true },
  autoApprovalEnabled: { type: Boolean, default: false },
  shippingRates: {
    localNAD: { type: Number, min: 0, default: 30 },
    hubNAD: { type: Number, min: 0, default: 70 },
    remoteNAD: { type: Number, min: 0, default: 120 },
    freeThresholdNAD: { type: Number, min: 0, default: 800 }
  },
  assistantPlanActive: { type: Boolean, default: false },
  assistantEnabled: { type: Boolean, default: false },
  kycStatus: { type: String, enum: ['not_submitted', 'pending', 'verified', 'rejected'], default: 'not_submitted', index: true },
  kycBusinessName: { type: String, trim: true, maxlength: 120, default: '' },
  kycDocumentType: { type: String, enum: ['', 'business_registration', 'tax_certificate', 'other_business_document'], default: '' },
  kycDocumentId: { type: String, default: '' },
  kycDocumentMime: { type: String, default: '' },
  kycSubmittedAt: { type: Date, default: null },
  kycReviewedAt: { type: Date, default: null },
  kycReviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  kycReviewNote: { type: String, trim: true, maxlength: 500, default: '' }
}, { timestamps: true });
const productSchema = new mongoose.Schema({
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true, index: true },
  title: { type: String, required: true, trim: true, maxlength: 100 },
  description: { type: String, required: true, trim: true, maxlength: 1500 },
  priceNAD: { type: Number, required: true, min: 0.01 },
  stock: { type: Number, min: 0, max: 100000, default: null },
  isAvailable: { type: Boolean, default: true },
  category: { type: String, required: true },
  town: { type: String, required: true },
  imageUrl: { type: String, default: '' },
  imageUrls: { type: [String], default: [] },
  status: { type: String, enum: ['active', 'archived'], default: 'active' },
  moderationStatus: { type: String, enum: ['visible', 'hidden'], default: 'visible' },
  moderatedAt: { type: Date, default: null }
}, { timestamps: true });
const listingReportSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  reporterId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reason: { type: String, enum: ['misleading', 'counterfeit', 'unsafe', 'prohibited', 'other'], required: true },
  details: { type: String, default: '', trim: true, maxlength: 500 },
  status: { type: String, enum: ['pending', 'dismissed', 'actioned'], default: 'pending', index: true }
}, { timestamps: true });
listingReportSchema.index({ productId: 1, reporterId: 1 }, { unique: true });
const shopReviewSchema = new mongoose.Schema({
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String, default: '', trim: true, maxlength: 500 }
}, { timestamps: true });
shopReviewSchema.index({ shopId: 1, userId: 1 }, { unique: true });
const orderLineSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  title: { type: String, required: true },
  quantity: { type: Number, required: true, min: 1 },
  unitPriceNAD: { type: Number, required: true, min: 0 },
  imageUrl: { type: String, default: '' }
}, { _id: false });
const sellerOrderSchema = new mongoose.Schema({
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  shopName: { type: String, required: true },
  sellerTown: { type: String, required: true },
  deliveryTown: { type: String, required: true },
  shippingZone: { type: String, enum: ['local', 'hub', 'remote'], required: true },
  items: { type: [orderLineSchema], required: true },
  productsSubtotalNAD: { type: Number, required: true, min: 0 },
  shippingNAD: { type: Number, required: true, min: 0 },
  commissionNAD: { type: Number, required: true, min: 0 },
  payoutNAD: { type: Number, required: true, min: 0 },
  approvalStatus: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending', index: true },
  fulfillmentStatus: { type: String, enum: ['awaiting_payment', 'processing', 'shipped', 'delivered', 'disputed'], default: 'awaiting_payment' },
  payoutStatus: { type: String, enum: ['held', 'eligible', 'paid', 'disputed'], default: 'held' },
  trackingReference: { type: String, default: '' },
  deliveredAt: { type: Date, default: null },
  payoutEligibleAt: { type: Date, default: null },
  payoutReference: { type: String, default: '' },
  payoutMarkedAt: { type: Date, default: null }
}, { timestamps: true });
const orderSchema = new mongoose.Schema({
  orderNumber: { type: String, required: true, unique: true },
  buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  deliveryTown: { type: String, required: true },
  items: { type: [orderLineSchema], required: true },
  sellerOrders: { type: [sellerOrderSchema], required: true },
  productsSubtotalNAD: { type: Number, required: true, min: 0 },
  shippingNAD: { type: Number, required: true, min: 0 },
  commissionNAD: { type: Number, required: true, min: 0 },
  totalNAD: { type: Number, required: true, min: 0 },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'expired', 'cancelled'], default: 'pending', index: true },
  paymentMode: { type: String, enum: ['mock'], default: 'mock' },
  paymentReference: { type: String, default: '' },
  reservationExpiresAt: { type: Date, required: true, index: true },
  reservationsReleasedAt: { type: Date, default: null },
  paidAt: { type: Date, default: null }
}, { timestamps: true });
const supportRequestSchema = new mongoose.Schema({
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true, index: true },
  orderNumber: { type: String, required: true, index: true },
  buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  topic: { type: String, enum: ['delivery', 'refund', 'return', 'item_issue', 'other'], required: true },
  message: { type: String, required: true, trim: true, maxlength: 1500 },
  status: { type: String, enum: ['open', 'in_review', 'resolved'], default: 'open', index: true },
  adminResponse: { type: String, default: '', trim: true, maxlength: 1000 }
}, { timestamps: true });
supportRequestSchema.index({ status: 1, createdAt: 1 });
const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const PasswordReset = mongoose.model('PasswordReset', passwordResetSchema);
const Shop = mongoose.model('Shop', shopSchema);
const Product = mongoose.model('Product', productSchema);
const ListingReport = mongoose.model('ListingReport', listingReportSchema);
const ShopReview = mongoose.model('ShopReview', shopReviewSchema);
const Order = mongoose.model('Order', orderSchema);
const SupportRequest = mongoose.model('SupportRequest', supportRequestSchema);
const productCategories = ['Art & Crafts', 'Beauty', 'Electronics', 'Fashion', 'Food', 'Home'];
const namibianTowns = ['Windhoek', 'Swakopmund', 'Walvis Bay', 'Oshakati', 'Rundu', 'Otjiwarongo', 'Other'];
const hubTowns = new Set(['Windhoek', 'Swakopmund', 'Walvis Bay', 'Oshakati', 'Rundu', 'Otjiwarongo']);
const commissionRate = Number(process.env.PLATFORM_COMMISSION_RATE || 0.1);
const reservationDurationMs = Number(process.env.ORDER_RESERVATION_MINUTES || 15) * 60 * 1000;
const payoutHoldDurationMs = Number(process.env.PAYOUT_HOLD_HOURS || 72) * 60 * 60 * 1000;
const payoutProcessingDurationMs = Number(process.env.PAYOUT_PROCESSING_HOURS || process.env.PAYOUT_HOLD_HOURS || 72) * 60 * 60 * 1000;
if (![payoutHoldDurationMs, payoutProcessingDurationMs].every((duration) => Number.isFinite(duration) && duration > 0)) {
  throw new Error('PAYOUT_HOLD_HOURS and PAYOUT_PROCESSING_HOURS must be positive numbers.');
}
const simulatedPayoutsEnabled = paymentAdapter.mode === 'mock' && process.env.NODE_ENV !== 'production' && process.env.SIMULATE_PAYOUTS !== 'false';
const payoutSweepSeconds = Number(process.env.PAYOUT_SWEEP_SECONDS || (simulatedPayoutsEnabled ? 1 : 60));
if (!Number.isFinite(payoutSweepSeconds) || payoutSweepSeconds < 1 || payoutSweepSeconds > 3600) {
  throw new Error('PAYOUT_SWEEP_SECONDS must be between 1 and 3600.');
}
const payoutSweepIntervalMs = payoutSweepSeconds * 1000;
const mockPaymentsEnabled = paymentAdapter.mode === 'mock' && process.env.NODE_ENV !== 'production' && process.env.MOCK_PAYMENTS_ENABLED !== 'false';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  }
}));
app.use(express.json({ limit: '10kb' }));
app.use(['/api/auth/register', '/api/auth/login'], authRateLimit);

app.get(['/dashboard', '/dashboard.html'], async (req, res) => {
  if (!await getSessionUser(req)) return res.redirect('/login');
  return res.sendFile(path.join(__dirname, '..', 'client', 'dashboard.html'));
});

app.get('/sell', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.exists({ ownerId: user._id });
  return res.redirect(shop ? '/sell/dashboard' : '/sell/setup');
});

app.get('/sell/setup', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  if (await Shop.exists({ ownerId: user._id })) return res.redirect('/sell/dashboard');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell-setup.html'));
});

app.get('/sell/dashboard', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  if (!await Shop.exists({ ownerId: user._id })) return res.redirect('/sell/setup');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell.html'));
});

app.get('/sell/profile', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  if (!await Shop.exists({ ownerId: user._id })) return res.redirect('/sell/setup');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell-profile.html'));
});

app.get('/sell/assistant', async (req, res) => {
  if (!await getSessionUser(req)) return res.redirect('/login');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell-assistant.html'));
});

app.get('/sell/verification', async (req, res) => {
  if (!await getSessionUser(req)) return res.redirect('/login');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell-verification.html'));
});

app.get('/terms', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'terms.html'));
});

app.get('/admin/payouts', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-payouts.html'));
});

app.get('/admin/moderation', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-moderation.html'));
});

app.get('/admin/support', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-support.html'));
});

app.get('/admin/kyc', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-kyc.html'));
});

app.get('/cart', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'cart.html'));
});

app.get('/checkout', async (req, res) => {
  if (!await getSessionUser(req)) return res.redirect('/login');
  return res.sendFile(path.join(__dirname, '..', 'client', 'checkout.html'));
});

app.get('/product/:id', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'product.html'));
});

app.get('/shops', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'shops.html'));
});

app.get('/shops/:slug', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'shop.html'));
});

app.use(express.static(path.join(__dirname, '..', 'client')));

function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function isAdminUser(user, configuredEmail = process.env.ADMIN_EMAIL, configuredId = process.env.ADMIN_USER_ID) {
  const adminEmail = normalizeEmail(configuredEmail);
  const configuredAdminId = configuredId || '';
  const userId = user?._id?.toString?.() || user?.id || '';
  const identityMatches = mongoose.isValidObjectId(configuredAdminId) && userId === configuredAdminId;
  return Boolean(adminEmail && user && normalizeEmail(user.email) === adminEmail && identityMatches);
}

function assertProductionAdminConfiguration(nodeEnv = process.env.NODE_ENV, adminEmail = process.env.ADMIN_EMAIL, adminUserId = process.env.ADMIN_USER_ID) {
  if (nodeEnv === 'production' && (!normalizeEmail(adminEmail) || !mongoose.isValidObjectId(adminUserId))) {
    throw new Error('Production startup blocked: configure ADMIN_EMAIL and the verified account ADMIN_USER_ID.');
  }
}

function publicUser(user) {
  return { id: user.id || user._id.toString(), name: user.name, email: user.email, isModerator: isAdminUser(user) };
}

function setSessionCookie(res, token, maxAge) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${sessionCookie}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`);
}

function getSessionToken(req) {
  const cookie = req.headers.cookie?.split(';').map((item) => item.trim()).find((item) => item.startsWith(`${sessionCookie}=`));
  return cookie?.slice(sessionCookie.length + 1) || '';
}

function hashSessionToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

async function createSession(res, user) {
  const token = randomBytes(32).toString('hex');
  await Session.create({
    tokenHash: hashSessionToken(token),
    userId: user._id,
    expiresAt: new Date(Date.now() + sessionDuration)
  });
  setSessionCookie(res, token, Math.floor(sessionDuration / 1000));
}

async function getSessionUser(req) {
  const token = getSessionToken(req);
  if (!token) return null;

  const session = await Session.findOne({
    tokenHash: hashSessionToken(token),
    expiresAt: { $gt: new Date() }
  }).populate('userId');

  return session?.userId || null;
}

function apiError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function normalizeSupportRequest(input = {}) {
  const topic = input.topic;
  const message = typeof input.message === 'string' ? input.message.trim() : '';
  if (!['delivery', 'refund', 'return', 'item_issue', 'other'].includes(topic) || message.length < 10 || message.length > 1500) {
    throw apiError(400, 'Choose a support topic and enter a message between 10 and 1500 characters.');
  }
  return { topic, message };
}

function normalizePasswordResetInput(input = {}) {
  const token = typeof input.token === 'string' ? input.token : '';
  const password = input.password;
  if (!/^[a-f0-9]{64}$/.test(token) || typeof password !== 'string' || password.length < 8 || password.length > 128) {
    throw apiError(400, 'Use a valid reset link and a password between 8 and 128 characters.');
  }
  return { token, password };
}

function assertProductionPaymentConfiguration(
  nodeEnv = process.env.NODE_ENV,
  paymentMode = paymentAdapter.mode,
  mockPaymentsEnabled = process.env.MOCK_PAYMENTS_ENABLED !== 'false'
) {
  if (nodeEnv === 'production' && paymentMode === 'mock' && mockPaymentsEnabled) {
    throw new Error('Production startup blocked: configure live payments or set MOCK_PAYMENTS_ENABLED=false to disable checkout.');
  }
}

function resolvePayoutStatus(sellerOrder, now, processingDurationMs, simulatePayouts) {
  const currentStatus = sellerOrder?.payoutStatus || 'held';
  const eligibleAt = sellerOrder?.payoutEligibleAt ? new Date(sellerOrder.payoutEligibleAt) : null;
  if (sellerOrder?.fulfillmentStatus !== 'delivered' || !eligibleAt || eligibleAt > now) return currentStatus;
  if (currentStatus === 'held') return 'eligible';
  if (currentStatus === 'eligible' && simulatePayouts && eligibleAt.getTime() + processingDurationMs <= now.getTime()) return 'paid';
  return currentStatus;
}

function roundNAD(value) {
  return Math.round((value + Number.EPSILON) * 100) / 100;
}

function normalizeCartItems(rawItems) {
  if (!Array.isArray(rawItems) || rawItems.length === 0 || rawItems.length > 30) {
    throw apiError(400, 'Your cart must contain between 1 and 30 different products.');
  }

  const quantities = new Map();
  for (const item of rawItems) {
    if (!mongoose.isValidObjectId(item?.id) || !Number.isInteger(item?.quantity) || item.quantity < 1 || item.quantity > 99) {
      throw apiError(400, 'Your cart has an invalid product or quantity.');
    }
    const id = item.id.toString();
    const quantity = (quantities.get(id) || 0) + item.quantity;
    if (quantity > 99) throw apiError(400, 'A product quantity cannot exceed 99.');
    quantities.set(id, quantity);
  }

  return [...quantities].map(([id, quantity]) => ({ id, quantity }));
}

function resolveShippingZone(sellerTown, deliveryTown) {
  if (sellerTown === deliveryTown) return 'local';
  if (hubTowns.has(sellerTown) && hubTowns.has(deliveryTown)) return 'hub';
  return 'remote';
}

async function buildOrderQuote(rawItems, deliveryTown) {
  if (!namibianTowns.includes(deliveryTown)) throw apiError(400, 'Choose a valid delivery town.');
  const requestedItems = normalizeCartItems(rawItems);
  const products = await Product.find({
    _id: { $in: requestedItems.map((item) => item.id) },
    status: 'active',
    isAvailable: { $ne: false },
    moderationStatus: { $ne: 'hidden' }
  }).populate('shopId');
  const productsById = new Map(products.map((product) => [product._id.toString(), product]));
  const groups = new Map();
  const items = [];

  for (const requested of requestedItems) {
    const product = productsById.get(requested.id);
    if (!product?.shopId) throw apiError(409, 'A product in your cart is no longer available. Refresh the cart and try again.');
    if (!Number.isInteger(product.stock) || product.stock < requested.quantity) {
      throw apiError(409, `${product.title} does not have enough stock available.`);
    }

    const item = {
      productId: product._id,
      title: product.title,
      quantity: requested.quantity,
      unitPriceNAD: product.priceNAD,
      imageUrl: product.imageUrl || ''
    };
    items.push(item);
    const shopId = product.shopId._id.toString();
    if (!groups.has(shopId)) groups.set(shopId, { shop: product.shopId, items: [] });
    groups.get(shopId).items.push(item);
  }

  const sellerOrders = [...groups.values()].map(({ shop, items: sellerItems }) => {
    const productsSubtotalNAD = roundNAD(sellerItems.reduce((sum, item) => sum + item.unitPriceNAD * item.quantity, 0));
    const shippingZone = resolveShippingZone(shop.town, deliveryTown);
    const rates = shop.shippingRates || {};
    const rateKey = `${shippingZone}NAD`;
    const freeThresholdNAD = rates.freeThresholdNAD ?? 800;
    const shippingNAD = freeThresholdNAD > 0 && productsSubtotalNAD >= freeThresholdNAD
      ? 0
      : roundNAD(rates[rateKey] ?? ({ local: 30, hub: 70, remote: 120 }[shippingZone]));
    const commissionNAD = roundNAD(productsSubtotalNAD * commissionRate);

    return {
      shopId: shop._id,
      sellerId: shop.ownerId,
      shopName: shop.name,
      sellerTown: shop.town,
      deliveryTown,
      shippingZone,
      items: sellerItems,
      productsSubtotalNAD,
      shippingNAD,
      commissionNAD,
      payoutNAD: roundNAD(productsSubtotalNAD - commissionNAD + shippingNAD),
      approvalStatus: 'pending',
      fulfillmentStatus: 'awaiting_payment',
      payoutStatus: 'held'
    };
  });

  const productsSubtotalNAD = roundNAD(sellerOrders.reduce((sum, sellerOrder) => sum + sellerOrder.productsSubtotalNAD, 0));
  const shippingNAD = roundNAD(sellerOrders.reduce((sum, sellerOrder) => sum + sellerOrder.shippingNAD, 0));
  const commissionNAD = roundNAD(sellerOrders.reduce((sum, sellerOrder) => sum + sellerOrder.commissionNAD, 0));

  return {
    items,
    sellerOrders,
    productsSubtotalNAD,
    shippingNAD,
    commissionNAD,
    totalNAD: roundNAD(productsSubtotalNAD + shippingNAD)
  };
}

async function reserveOrderStock(items) {
  const reserved = [];
  try {
    for (const item of items) {
      const product = await Product.findOneAndUpdate({
        _id: item.productId,
        status: 'active',
        isAvailable: { $ne: false },
        stock: { $gte: item.quantity }
      }, { $inc: { stock: -item.quantity } }, { new: true });

      if (!product) throw apiError(409, 'Stock changed while checking out. Review your cart and try again.');
      reserved.push(item);
      if (product.stock === 0) {
        await Product.updateOne({ _id: product._id, stock: 0 }, { $set: { isAvailable: false } });
      }
    }
  } catch (error) {
    await releaseReservedStock(reserved);
    throw error;
  }
}

async function releaseReservedStock(items) {
  for (const item of items) {
    const result = await Product.updateOne({ _id: item.productId, stock: { $ne: null } }, { $inc: { stock: item.quantity } });
    if (result.matchedCount) {
      await Product.updateOne({ _id: item.productId, stock: { $gt: 0 } }, { $set: { isAvailable: true } });
    }
  }
}

function resolveSellerApprovalState(autoApprovalEnabled) {
  return autoApprovalEnabled ? 'accepted' : 'pending';
}

function normalizeImageUrls(input) {
  const values = Array.isArray(input) ? input : [input];
  const seen = new Set();
  return values.flatMap((value) => {
    if (typeof value !== 'string') return [];
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) return [];
    seen.add(trimmed);
    return [trimmed];
  }).slice(0, 6);
}

function validateImageUrl(url) {
  if (!url) return true;
  try {
    return new URL(url).protocol === 'https:' && url.length <= 2048;
  } catch {
    return false;
  }
}

function hasValidImageSignature(file) {
  if (!file?.buffer) return false;
  if (file.mimetype === 'image/jpeg') return file.buffer.length >= 3 && file.buffer[0] === 0xff && file.buffer[1] === 0xd8 && file.buffer[2] === 0xff;
  if (file.mimetype === 'image/png') return file.buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  if (file.mimetype === 'image/webp') return file.buffer.toString('ascii', 0, 4) === 'RIFF' && file.buffer.toString('ascii', 8, 12) === 'WEBP';
  return false;
}

function getBuyerDisplayName(order) {
  const buyerName = order?.buyerId && typeof order.buyerId === 'object' ? order.buyerId.name : '';
  const cleanName = typeof buyerName === 'string' ? buyerName.trim() : '';
  return cleanName || 'Customer';
}

function canCancelOrder(order) {
  if (!order || ['cancelled', 'expired'].includes(order.paymentStatus)) return false;

  if (order.paymentStatus === 'pending') {
    return Boolean(order.reservationExpiresAt && new Date(order.reservationExpiresAt) > new Date());
  }

  if (order.paymentStatus === 'paid') {
    const approvalStates = Array.isArray(order.sellerOrders)
      ? order.sellerOrders.map((sellerOrder) => sellerOrder?.approvalStatus).filter(Boolean)
      : [];
    return approvalStates.length > 0 && approvalStates.every((status) => status === 'pending');
  }

  return false;
}

async function releaseExpiredReservations() {
  const expired = await Order.find({
    paymentStatus: 'pending',
    reservationExpiresAt: { $lte: new Date() },
    reservationsReleasedAt: null
  }).limit(100).select('_id items');

  for (const candidate of expired) {
    const order = await Order.findOneAndUpdate({
      _id: candidate._id,
      paymentStatus: 'pending',
      reservationsReleasedAt: null
    }, { $set: { paymentStatus: 'expired', reservationsReleasedAt: new Date() } }, { new: true }).select('items');
    if (order) await releaseReservedStock(order.items);
  }
}

async function advancePayoutLifecycle() {
  const now = new Date();
  const orders = await Order.find({
    paymentStatus: 'paid',
    sellerOrders: { $elemMatch: {
      fulfillmentStatus: 'delivered',
      payoutStatus: { $in: ['held', 'eligible'] },
      payoutEligibleAt: { $lte: now }
    } }
  }).sort({ updatedAt: 1 }).limit(100).select('_id sellerOrders');

  for (const order of orders) {
    for (const sellerOrder of order.sellerOrders) {
      const currentStatus = sellerOrder.payoutStatus;
      const nextStatus = resolvePayoutStatus(sellerOrder, now, payoutProcessingDurationMs, simulatedPayoutsEnabled);
      if (nextStatus === currentStatus) continue;

      const updates = { 'sellerOrders.$.payoutStatus': nextStatus };
      if (nextStatus === 'paid' && simulatedPayoutsEnabled) {
        updates['sellerOrders.$.payoutReference'] = `SIM-${randomBytes(6).toString('hex').toUpperCase()}`;
        updates['sellerOrders.$.payoutMarkedAt'] = now;
      }

      await Order.updateOne({
        _id: order._id,
        paymentStatus: 'paid',
        sellerOrders: { $elemMatch: {
          _id: sellerOrder._id,
          fulfillmentStatus: 'delivered',
          payoutStatus: currentStatus,
          payoutEligibleAt: { $lte: now }
        } }
      }, { $set: updates });
    }
  }
}



app.post('/api/auth/register', async (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;

  if (!name || name.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Enter a valid name and email, and a password between 8 and 128 characters.' });
  }

  const salt = randomBytes(16).toString('hex');
  const passwordHash = (await scryptAsync(password, salt, 64)).toString('hex');
  let user;
  try {
    user = await User.create({ name, email, salt, passwordHash });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ error: 'An account with that email already exists. Try signing in.' });
    }
    throw error;
  }

  await createSession(res, user);

  return res.status(201).json({ user: publicUser(user) });
});

app.post('/api/auth/login', async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;
  const user = await User.findOne({ email });

  if (typeof password !== 'string' || !user || password.length > 128) {
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  }

  const passwordHash = await scryptAsync(password, user.salt, 64);
  if (!timingSafeEqual(passwordHash, Buffer.from(user.passwordHash, 'hex'))) {
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  }

  await createSession(res, user);
  return res.json({ user: publicUser(user) });
});

app.post('/api/auth/forgot-password', passwordResetRateLimit, async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (process.env.NODE_ENV === 'production' && (!passwordResetMailer || !process.env.APP_BASE_URL?.startsWith('https://'))) {
    return res.status(503).json({ error: 'Password reset email is not configured. Contact Z support.' });
  }

  const user = await User.findOne({ email }).select('_id email name');
  if (!user) return res.status(202).json({ message: 'If an account exists for that email, password reset instructions will be sent.' });

  const token = randomBytes(32).toString('hex');
  await PasswordReset.deleteMany({ userId: user._id });
  await PasswordReset.create({
    tokenHash: hashSessionToken(token),
    userId: user._id,
    expiresAt: new Date(Date.now() + 15 * 60 * 1000)
  });
  const baseUrl = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3001}`;
  const resetUrl = new URL(`/reset-password?token=${encodeURIComponent(token)}`, baseUrl).toString();

  if (process.env.NODE_ENV === 'production') {
    try {
      await passwordResetMailer.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: 'Reset your Z password',
        text: `Hello ${user.name},\n\nUse this link within 15 minutes to reset your Z password:\n${resetUrl}\n\nIf you did not request this, you can ignore this email.`
      });
    } catch (error) {
      console.error('Password reset email delivery failed:', error.message);
    }
    return res.status(202).json({ message: 'If an account exists for that email, password reset instructions will be sent.' });
  }

  return res.status(202).json({
    message: 'If an account exists for that email, password reset instructions will be sent.',
    resetUrl
  });
});

app.post('/api/auth/reset-password', passwordResetRateLimit, async (req, res) => {
  const { token, password } = normalizePasswordResetInput(req.body);

  const reset = await PasswordReset.findOneAndDelete({
    tokenHash: hashSessionToken(token),
    expiresAt: { $gt: new Date() }
  });
  if (!reset) return res.status(400).json({ error: 'This password reset link is invalid or has expired. Request a new one.' });

  const user = await User.findById(reset.userId);
  if (!user) return res.status(400).json({ error: 'This password reset link is invalid or has expired. Request a new one.' });
  const salt = randomBytes(16).toString('hex');
  user.salt = salt;
  user.passwordHash = (await scryptAsync(password, salt, 64)).toString('hex');
  await user.save();
  await Promise.all([
    Session.deleteMany({ userId: user._id }),
    PasswordReset.deleteMany({ userId: user._id })
  ]);
  return res.json({ ok: true, message: 'Your password has been reset. Sign in with your new password.' });
});

app.get('/api/auth/me', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not signed in.' });
  return res.json({ user: publicUser(user) });
});

app.get('/api/auth/status', async (req, res) => {
  const user = await getSessionUser(req);
  return res.json({ user: user ? publicUser(user) : null });
});

app.post('/api/auth/logout', async (req, res) => {
  const token = getSessionToken(req);
  if (token) await Session.deleteOne({ tokenHash: hashSessionToken(token) });
  setSessionCookie(res, '', 0);
  return res.json({ ok: true });
});

app.post('/api/orders/quote', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to continue to checkout.' });
  await releaseExpiredReservations();
  const quote = await buildOrderQuote(req.body?.items, req.body?.deliveryTown);
  return res.json({
    currency: 'NAD',
    commissionRate,
    items: quote.items.map((item) => ({ productId: item.productId, title: item.title, quantity: item.quantity, unitPriceNAD: item.unitPriceNAD })),
    sellerOrders: quote.sellerOrders.map((sellerOrder) => ({
      shopId: sellerOrder.shopId,
      shopName: sellerOrder.shopName,
      sellerTown: sellerOrder.sellerTown,
      deliveryTown: sellerOrder.deliveryTown,
      shippingZone: sellerOrder.shippingZone,
      items: sellerOrder.items.map((item) => ({ productId: item.productId, title: item.title, quantity: item.quantity, unitPriceNAD: item.unitPriceNAD })),
      productsSubtotalNAD: sellerOrder.productsSubtotalNAD,
      shippingNAD: sellerOrder.shippingNAD
    })),
    productsSubtotalNAD: quote.productsSubtotalNAD,
    shippingNAD: quote.shippingNAD,
    totalNAD: quote.totalNAD
  });
});

app.post('/api/orders', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to place an order.' });
  if (!mockPaymentsEnabled) return res.status(503).json({ error: 'Mock checkout is disabled. A live payment provider is not configured.' });
  await releaseExpiredReservations();
  const quote = await buildOrderQuote(req.body?.items, req.body?.deliveryTown);
  await reserveOrderStock(quote.items);

  const orderNumber = `Z-${Date.now()}-${randomBytes(2).toString('hex').toUpperCase()}`;
  const paymentIntent = paymentAdapter.createIntent(orderNumber);
  let order;
  try {
    order = await Order.create({
      orderNumber,
      buyerId: user._id,
      deliveryTown: req.body.deliveryTown,
      items: quote.items,
      sellerOrders: quote.sellerOrders,
      productsSubtotalNAD: quote.productsSubtotalNAD,
      shippingNAD: quote.shippingNAD,
      commissionNAD: quote.commissionNAD,
      totalNAD: quote.totalNAD,
      paymentMode: 'mock',
      paymentReference: paymentIntent.reference,
      reservationExpiresAt: new Date(Date.now() + reservationDurationMs)
    });
  } catch (error) {
    await releaseReservedStock(quote.items);
    throw error;
  }

  return res.status(201).json({
    orderNumber: order.orderNumber,
    paymentStatus: order.paymentStatus,
    paymentMode: order.paymentMode,
    paymentIntent,
    reservationExpiresAt: order.reservationExpiresAt,
    sellerOrders: order.sellerOrders.map((sellerOrder) => ({
      shopName: sellerOrder.shopName,
      productsSubtotalNAD: sellerOrder.productsSubtotalNAD,
      shippingNAD: sellerOrder.shippingNAD,
      commissionNAD: sellerOrder.commissionNAD,
      payoutNAD: sellerOrder.payoutNAD,
      shippingZone: sellerOrder.shippingZone
    })),
    productsSubtotalNAD: order.productsSubtotalNAD,
    shippingNAD: order.shippingNAD,
    commissionNAD: order.commissionNAD,
    totalNAD: order.totalNAD
  });
});

app.post('/api/orders/:orderNumber/mock-payment', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to confirm this test payment.' });
  if (!mockPaymentsEnabled) return res.status(503).json({ error: 'Mock payments are disabled.' });
  await releaseExpiredReservations();

  const order = await Order.findOne({ orderNumber: req.params.orderNumber, buyerId: user._id });
  if (!order) return res.status(404).json({ error: 'Order not found.' });
  if (order.paymentStatus !== 'pending' || order.reservationExpiresAt <= new Date()) {
    return res.status(409).json({ error: 'This test payment is no longer pending. Create a new order.' });
  }

  const payment = paymentAdapter.confirmIntent(order.paymentReference);
  const shops = await Shop.find({ _id: { $in: order.sellerOrders.map((sellerOrder) => sellerOrder.shopId) } }).select('_id autoApprovalEnabled').lean();
  const autoApprovalByShop = new Map(shops.map((shop) => [shop._id.toString(), Boolean(shop.autoApprovalEnabled)]));
  const sellerOrders = order.sellerOrders.map((sellerOrder) => {
    const autoApprovalEnabled = autoApprovalByShop.get(sellerOrder.shopId.toString()) ?? false;
    const approvalStatus = resolveSellerApprovalState(autoApprovalEnabled);
    return {
      ...sellerOrder.toObject ? sellerOrder.toObject() : sellerOrder,
      approvalStatus,
      fulfillmentStatus: approvalStatus === 'accepted' ? 'processing' : 'awaiting_payment',
      payoutStatus: 'held'
    };
  });

  const paidOrder = await Order.findOneAndUpdate({
    _id: order._id,
    buyerId: user._id,
    paymentStatus: 'pending',
    reservationExpiresAt: { $gt: new Date() },
    reservationsReleasedAt: null
  }, {
    $set: {
      paymentStatus: 'paid',
      paymentReference: payment.reference,
      paidAt: payment.confirmedAt,
      sellerOrders
    }
  }, { new: true });

  if (!paidOrder) return res.status(409).json({ error: 'Order changed before the mock payment was confirmed.' });
  return res.json({ orderNumber: paidOrder.orderNumber, paymentStatus: paidOrder.paymentStatus, mock: true, message: 'Test payment recorded. No money was charged.' });
});

app.get('/api/orders/mine', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view orders.' });
  await releaseExpiredReservations();
  const orders = await Order.find({ buyerId: user._id }).sort({ createdAt: -1 }).lean();
  const supportRequests = await SupportRequest.find({ buyerId: user._id }).sort({ createdAt: -1 }).lean();
  const requestsByOrder = new Map();
  supportRequests.forEach((request) => {
    const key = request.orderId.toString();
    if (!requestsByOrder.has(key)) requestsByOrder.set(key, []);
    requestsByOrder.get(key).push({
      id: request._id.toString(),
      topic: request.topic,
      message: request.message,
      status: request.status,
      adminResponse: request.adminResponse,
      createdAt: request.createdAt,
      updatedAt: request.updatedAt
    });
  });
  return res.json({ orders: orders.map((order) => ({
    ...order,
    supportRequests: requestsByOrder.get(order._id.toString()) || []
  })) });
});

app.post('/api/orders/:orderNumber/support', supportRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to contact support.' });
  const order = await Order.findOne({ orderNumber: req.params.orderNumber, buyerId: user._id }).select('_id orderNumber');
  if (!order) return res.status(404).json({ error: 'Order not found.' });

  const { topic, message } = normalizeSupportRequest(req.body);
  const request = await SupportRequest.create({
    orderId: order._id,
    orderNumber: order.orderNumber,
    buyerId: user._id,
    topic,
    message
  });
  return res.status(201).json({ request: {
    id: request._id.toString(),
    topic: request.topic,
    message: request.message,
    status: request.status,
    adminResponse: request.adminResponse,
    createdAt: request.createdAt,
    updatedAt: request.updatedAt
  } });
});

app.get('/api/seller/orders', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view seller orders.' });
  const orders = await Order.find({ 'sellerOrders.sellerId': user._id, paymentStatus: 'paid' })
    .populate('buyerId', 'name email')
    .sort({ createdAt: -1 })
    .lean();

  const sellerOrders = orders.flatMap((order) => order.sellerOrders
    .filter((sellerOrder) => sellerOrder.sellerId.toString() === user._id.toString())
    .map((sellerOrder) => ({
      orderNumber: order.orderNumber,
      orderCreatedAt: order.createdAt,
      paidAt: order.paidAt,
      paymentStatus: order.paymentStatus,
      deliveryTown: order.deliveryTown,
      buyerName: getBuyerDisplayName(order),
      buyerId: order.buyerId ? { id: order.buyerId._id?.toString?.() || order.buyerId.toString?.(), name: order.buyerId.name || 'Customer' } : null,
      ...sellerOrder,
      payoutMode: simulatedPayoutsEnabled ? 'simulated' : 'manual',
      payoutProcessingAt: sellerOrder.payoutEligibleAt
        ? new Date(new Date(sellerOrder.payoutEligibleAt).getTime() + payoutProcessingDurationMs)
        : null
    })));
  return res.json({ sellerOrders });
});

app.post('/api/seller/orders/:orderNumber/:sellerOrderId/decision', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to approve or reject an order.' });
  if (!mongoose.isValidObjectId(req.params.sellerOrderId)) return res.status(404).json({ error: 'Seller order not found.' });
  const decision = req.body?.decision;
  if (!['accept', 'reject'].includes(decision)) return res.status(400).json({ error: 'Choose whether to accept or reject this order.' });

  const order = await Order.findOneAndUpdate({
    orderNumber: req.params.orderNumber,
    paymentStatus: 'paid',
    sellerOrders: { $elemMatch: { _id: req.params.sellerOrderId, sellerId: user._id, approvalStatus: 'pending' } }
  }, { $set: {
    'sellerOrders.$.approvalStatus': decision === 'accept' ? 'accepted' : 'rejected',
    'sellerOrders.$.fulfillmentStatus': decision === 'accept' ? 'processing' : 'disputed',
    'sellerOrders.$.payoutStatus': decision === 'accept' ? 'held' : 'disputed'
  } }, { new: true });
  if (!order) return res.status(404).json({ error: 'An order awaiting approval was not found.' });
  return res.json({ orderNumber: order.orderNumber, approvalStatus: decision === 'accept' ? 'accepted' : 'rejected', fulfillmentStatus: order.sellerOrders.find((sellerOrder) => sellerOrder._id.toString() === req.params.sellerOrderId)?.fulfillmentStatus || 'disputed' });
});

app.patch('/api/seller/orders/:orderNumber/:sellerOrderId/shipping', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to update shipping.' });
  if (!mongoose.isValidObjectId(req.params.sellerOrderId)) return res.status(404).json({ error: 'Seller order not found.' });
  const trackingReference = typeof req.body?.trackingReference === 'string' ? req.body.trackingReference.trim() : '';
  if (trackingReference.length < 2 || trackingReference.length > 100) return res.status(400).json({ error: 'Enter a valid tracking reference.' });

  const order = await Order.findOneAndUpdate({
    orderNumber: req.params.orderNumber,
    paymentStatus: 'paid',
    sellerOrders: { $elemMatch: { _id: req.params.sellerOrderId, sellerId: user._id, approvalStatus: 'accepted', fulfillmentStatus: 'processing' } }
  }, { $set: { 'sellerOrders.$.fulfillmentStatus': 'shipped', 'sellerOrders.$.trackingReference': trackingReference } }, { new: true });
  if (!order) return res.status(404).json({ error: 'An accepted seller order was not found.' });
  return res.json({ orderNumber: order.orderNumber, status: 'shipped', trackingReference });
});

app.post('/api/orders/:orderNumber/cancel', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to cancel your order.' });

  const order = await Order.findOne({ orderNumber: req.params.orderNumber, buyerId: user._id }).lean();
  if (!order) return res.status(404).json({ error: 'Order not found.' });
  if (!canCancelOrder(order)) return res.status(409).json({ error: 'This order cannot be cancelled anymore.' });

  const update = { paymentStatus: 'cancelled', reservationsReleasedAt: new Date() };
  if (order.paymentStatus === 'paid') {
    update['sellerOrders.$[].fulfillmentStatus'] = 'disputed';
    update['sellerOrders.$[].payoutStatus'] = 'disputed';
  }

  const cancelledOrder = await Order.findOneAndUpdate({
    _id: order._id,
    buyerId: user._id,
    paymentStatus: { $in: ['pending', 'paid'] }
  }, {
    $set: update
  }, { new: true });
  if (!cancelledOrder) return res.status(409).json({ error: 'This order changed before it could be cancelled.' });

  await releaseReservedStock(cancelledOrder.items);
  return res.json({ ok: true, orderNumber: cancelledOrder.orderNumber, paymentStatus: cancelledOrder.paymentStatus });
});

app.post('/api/orders/:orderNumber/:sellerOrderId/confirm-delivery', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to confirm delivery.' });
  if (!mongoose.isValidObjectId(req.params.sellerOrderId)) return res.status(404).json({ error: 'Seller order not found.' });
  const now = new Date();
  const payoutEligibleAt = new Date(now.getTime() + payoutHoldDurationMs);
  const order = await Order.findOneAndUpdate({
    orderNumber: req.params.orderNumber,
    buyerId: user._id,
    paymentStatus: 'paid',
    sellerOrders: { $elemMatch: { _id: req.params.sellerOrderId, fulfillmentStatus: 'shipped' } }
  }, { $set: {
    'sellerOrders.$.fulfillmentStatus': 'delivered',
    'sellerOrders.$.deliveredAt': now,
    'sellerOrders.$.payoutEligibleAt': payoutEligibleAt,
    'sellerOrders.$.payoutStatus': 'held'
  } }, { new: true });
  if (!order) return res.status(404).json({ error: 'A shipped seller order was not found.' });
  return res.json({ orderNumber: order.orderNumber, fulfillmentStatus: 'delivered', payoutStatus: 'held', payoutEligibleAt });
});

app.get('/api/seller/payout-ledger', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view seller balances.' });
  await advancePayoutLifecycle();
  const orders = await Order.find({ 'sellerOrders.sellerId': user._id, paymentStatus: 'paid' }).sort({ createdAt: -1 }).lean();
  const now = new Date();
  const entries = orders.flatMap((order) => order.sellerOrders
    .filter((sellerOrder) => sellerOrder.sellerId.toString() === user._id.toString())
    .map((sellerOrder) => ({
      orderNumber: order.orderNumber,
      shopName: sellerOrder.shopName,
      payoutNAD: sellerOrder.payoutNAD,
      payoutStatus: resolvePayoutStatus(sellerOrder, now, payoutProcessingDurationMs, simulatedPayoutsEnabled),
      payoutEligibleAt: sellerOrder.payoutEligibleAt,
      payoutProcessingAt: sellerOrder.payoutEligibleAt
        ? new Date(new Date(sellerOrder.payoutEligibleAt).getTime() + payoutProcessingDurationMs)
        : null,
      payoutMarkedAt: sellerOrder.payoutMarkedAt,
      payoutReference: sellerOrder.payoutReference,
      simulated: typeof sellerOrder.payoutReference === 'string' && sellerOrder.payoutReference.startsWith('SIM-')
    })));
  return res.json({ entries, mode: simulatedPayoutsEnabled ? 'simulated' : 'manual' });
});

app.get('/api/admin/payout-report', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  await advancePayoutLifecycle();
  const now = new Date();
  const orders = await Order.find({
    paymentStatus: 'paid',
    sellerOrders: { $elemMatch: { fulfillmentStatus: 'delivered', payoutStatus: { $in: ['held', 'eligible', 'paid'] } } }
  }).sort({ createdAt: 1 }).populate('sellerOrders.sellerId', 'name email').lean();
  const entries = orders.flatMap((order) => order.sellerOrders
    .filter((sellerOrder) => sellerOrder.fulfillmentStatus === 'delivered' && ['held', 'eligible', 'paid'].includes(sellerOrder.payoutStatus))
    .map((sellerOrder) => ({
      orderNumber: order.orderNumber,
      sellerOrderId: sellerOrder._id.toString(),
      sellerName: sellerOrder.sellerId?.name || 'Seller account unavailable',
      sellerEmail: sellerOrder.sellerId?.email || '',
      shopName: sellerOrder.shopName,
      productsSubtotalNAD: sellerOrder.productsSubtotalNAD,
      shippingNAD: sellerOrder.shippingNAD,
      commissionNAD: sellerOrder.commissionNAD,
      payoutNAD: sellerOrder.payoutNAD,
      payoutStatus: sellerOrder.payoutStatus,
      payoutEligibleAt: sellerOrder.payoutEligibleAt,
      payoutProcessingAt: sellerOrder.payoutEligibleAt
        ? new Date(new Date(sellerOrder.payoutEligibleAt).getTime() + payoutProcessingDurationMs)
        : null,
      payoutMarkedAt: sellerOrder.payoutMarkedAt,
      payoutReference: sellerOrder.payoutReference,
      eligible: sellerOrder.payoutStatus === 'eligible' || sellerOrder.payoutStatus === 'paid',
      simulated: simulatedPayoutsEnabled && sellerOrder.payoutStatus === 'paid'
    })));
  return res.json({ entries, generatedAt: now, mode: simulatedPayoutsEnabled ? 'simulated' : 'manual' });
});

app.get('/api/admin/support-requests', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  const requests = await SupportRequest.find().populate('buyerId', 'name email').sort({ status: 1, createdAt: 1 }).limit(200).lean();
  return res.json({ requests: requests.map((request) => ({
    id: request._id.toString(),
    orderNumber: request.orderNumber,
    buyer: request.buyerId ? { name: request.buyerId.name, email: request.buyerId.email } : null,
    topic: request.topic,
    message: request.message,
    status: request.status,
    adminResponse: request.adminResponse,
    createdAt: request.createdAt,
    updatedAt: request.updatedAt
  })) });
});

app.patch('/api/admin/support-requests/:id', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Support request not found.' });
  const status = req.body?.status;
  const adminResponse = typeof req.body?.adminResponse === 'string' ? req.body.adminResponse.trim() : '';
  if (!['open', 'in_review', 'resolved'].includes(status) || adminResponse.length > 1000) {
    return res.status(400).json({ error: 'Choose a valid status and keep the response under 1000 characters.' });
  }
  const request = await SupportRequest.findByIdAndUpdate(req.params.id, {
    $set: { status, adminResponse }
  }, { new: true, runValidators: true });
  if (!request) return res.status(404).json({ error: 'Support request not found.' });
  return res.json({ ok: true, status: request.status, adminResponse: request.adminResponse });
});

app.post('/api/admin/payout-report/:orderNumber/:sellerOrderId/mark-paid', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  if (simulatedPayoutsEnabled) return res.status(409).json({ error: 'Manual payout recording is disabled while mock payouts are being simulated.' });
  if (!mongoose.isValidObjectId(req.params.sellerOrderId)) return res.status(404).json({ error: 'Eligible payout not found.' });
  const reference = typeof req.body?.reference === 'string' ? req.body.reference.trim() : '';
  if (reference.length < 2 || reference.length > 100) return res.status(400).json({ error: 'Enter the manual EFT reference (2 to 100 characters).'});

  const order = await Order.findOneAndUpdate({
    orderNumber: req.params.orderNumber,
    paymentStatus: 'paid',
    sellerOrders: { $elemMatch: {
      _id: req.params.sellerOrderId,
      fulfillmentStatus: 'delivered',
      payoutStatus: 'eligible',
      payoutEligibleAt: { $lte: new Date() }
    } }
  }, { $set: {
    'sellerOrders.$.payoutStatus': 'paid',
    'sellerOrders.$.payoutReference': reference,
    'sellerOrders.$.payoutMarkedAt': new Date()
  } }, { new: true });

  if (!order) return res.status(409).json({ error: 'This payout is not eligible or has already been recorded.' });
  return res.json({ ok: true, orderNumber: order.orderNumber, payoutStatus: 'paid', reference });
});

app.get('/api/admin/reports', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });

  const reports = await ListingReport.find({ status: 'pending' })
    .sort({ createdAt: 1 })
    .populate({ path: 'productId', populate: { path: 'shopId', select: 'name slug' } })
    .populate('reporterId', 'name email')
    .lean();
  const productIds = [...new Set(reports.filter((report) => report.productId).map((report) => report.productId._id.toString()))];
  const counts = productIds.length
    ? await ListingReport.aggregate([
      { $match: { status: 'pending', productId: { $in: productIds.map((id) => new mongoose.Types.ObjectId(id)) } } },
      { $group: { _id: '$productId', count: { $sum: 1 } } }
    ])
    : [];
  const countByProduct = new Map(counts.map((entry) => [entry._id.toString(), entry.count]));

  const hiddenProducts = await Product.find({ moderationStatus: 'hidden', status: 'active' })
    .populate('shopId', 'name slug')
    .sort({ moderatedAt: -1, createdAt: -1 })
    .limit(50)
    .lean();

  const queue = [
    ...reports.map((report) => ({
      id: report._id.toString(),
      reason: report.reason,
      details: report.details,
      createdAt: report.createdAt,
      reportCount: report.productId ? countByProduct.get(report.productId._id.toString()) || 0 : 0,
      reporter: report.reporterId ? { name: report.reporterId.name, email: report.reporterId.email } : null,
      product: report.productId ? {
        id: report.productId._id.toString(),
        title: report.productId.title,
        description: report.productId.description,
        imageUrl: report.productId.imageUrl,
        moderationStatus: report.productId.moderationStatus || 'visible',
        shopName: report.productId.shopId?.name || 'Unknown shop'
      } : null
    })),
    ...hiddenProducts.map((product) => ({
      id: `hidden:${product._id.toString()}`,
      reason: 'Hidden by moderator',
      details: 'This listing was hidden by a moderator and can be restored without a new report.',
      createdAt: product.moderatedAt || product.updatedAt || product.createdAt,
      reportCount: 0,
      reporter: null,
      isHiddenProduct: true,
      product: {
        id: product._id.toString(),
        title: product.title,
        description: product.description,
        imageUrl: product.imageUrl,
        moderationStatus: product.moderationStatus || 'hidden',
        shopName: product.shopId?.name || 'Unknown shop'
      }
    }))
  ].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  return res.json({ reports: queue });
});

app.patch('/api/admin/reports/:id', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  const decision = req.body?.decision;
  if (!['hide', 'restore', 'dismiss'].includes(decision)) return res.status(400).json({ error: 'Choose whether to hide, restore, or dismiss the report.' });

  if (typeof req.params.id === 'string' && req.params.id.startsWith('hidden:')) {
    const productId = req.params.id.replace(/^hidden:/, '');
    if (!mongoose.isValidObjectId(productId)) return res.status(404).json({ error: 'Hidden product not found.' });
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ error: 'Hidden product not found.' });
    if (decision === 'dismiss') return res.status(400).json({ error: 'Hidden items cannot be dismissed. Use restore to make them visible again.' });
    product.moderationStatus = decision === 'hide' ? 'hidden' : 'visible';
    product.moderatedAt = decision === 'hide' ? new Date() : null;
    await product.save();
    return res.json({ ok: true, productId: product._id.toString(), moderationStatus: product.moderationStatus });
  }

  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Report not found.' });

  const report = await ListingReport.findOne({ _id: req.params.id, status: 'pending' });
  if (!report) return res.status(404).json({ error: 'Pending report not found.' });
  if (decision === 'dismiss') {
    report.status = 'dismissed';
    await report.save();
    return res.json({ ok: true, productId: report.productId.toString(), dismissed: true });
  }

  const moderationStatus = decision === 'hide' ? 'hidden' : 'visible';
  await Product.updateOne({ _id: report.productId }, {
    $set: { moderationStatus, moderatedAt: decision === 'hide' ? new Date() : null }
  });
  await ListingReport.updateMany({ productId: report.productId, status: 'pending' }, { $set: { status: 'actioned' } });
  return res.json({ ok: true, productId: report.productId.toString(), moderationStatus });
});

app.get('/api/admin/kyc', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  const shops = await Shop.find({ kycStatus: 'pending' })
    .select('name slug town kycStatus kycBusinessName kycDocumentType kycSubmittedAt')
    .populate('ownerId', 'name email')
    .sort({ kycSubmittedAt: 1 })
    .limit(100)
    .lean();
  return res.json({ submissions: shops.map((shop) => ({
    id: shop._id.toString(),
    shopName: shop.name,
    slug: shop.slug,
    town: shop.town,
    businessName: shop.kycBusinessName,
    documentType: shop.kycDocumentType,
    submittedAt: shop.kycSubmittedAt,
    owner: shop.ownerId ? { name: shop.ownerId.name, email: shop.ownerId.email } : null
  })) });
});

app.get('/api/admin/kyc/:shopId/document', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.shopId)) return res.status(404).json({ error: 'Verification document not found.' });
  const shop = await Shop.findById(req.params.shopId).select('kycStatus kycDocumentId kycDocumentMime').lean();
  if (shop?.kycStatus !== 'pending' || !shop?.kycDocumentId || !/^[a-f0-9-]{36}$/.test(shop.kycDocumentId)) return res.status(404).json({ error: 'Verification document not found.' });

  let document;
  try {
    const encryptedDocument = await fsPromises.readFile(path.join(kycStorageDirectory, `${shop.kycDocumentId}.enc`));
    document = decryptKycDocument(encryptedDocument, getKycEncryptionKey());
  } catch (error) {
    if (error.code === 'ENOENT') return res.status(404).json({ error: 'Verification document not found.' });
    if (error.message.includes('KYC')) return res.status(503).json({ error: error.message });
    throw error;
  }

  const extension = { 'application/pdf': 'pdf', 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' }[shop.kycDocumentMime];
  if (!extension || detectKycDocumentMime(document) !== shop.kycDocumentMime) return res.status(500).json({ error: 'Verification document could not be validated.' });
  res.set({
    'Cache-Control': 'private, no-store, max-age=0',
    'Content-Disposition': `attachment; filename="business-verification-document.${extension}"`,
    'Content-Type': shop.kycDocumentMime,
    'X-Content-Type-Options': 'nosniff'
  });
  return res.send(document);
});

app.patch('/api/admin/kyc/:shopId', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.shopId)) return res.status(404).json({ error: 'Verification submission not found.' });
  const status = req.body?.status;
  const reviewNote = typeof req.body?.reviewNote === 'string' ? req.body.reviewNote.trim() : '';
  if (!['verified', 'rejected'].includes(status) || reviewNote.length > 500 || (status === 'rejected' && reviewNote.length < 5)) {
    return res.status(400).json({ error: 'Choose approve or reject; rejected submissions require a short explanation.' });
  }

  const shop = await Shop.findOne({ _id: req.params.shopId, kycStatus: 'pending' });
  if (!shop) return res.status(404).json({ error: 'Pending verification submission not found.' });
  const documentId = shop.kycDocumentId;
  shop.kycStatus = status;
  shop.kycReviewedAt = new Date();
  shop.kycReviewedBy = user._id;
  shop.kycReviewNote = reviewNote;
  shop.kycDocumentId = '';
  shop.kycDocumentMime = '';
  await shop.save();
  if (documentId && /^[a-f0-9-]{36}$/.test(documentId)) {
    await fsPromises.unlink(path.join(kycStorageDirectory, `${documentId}.enc`)).catch(() => {});
  }
  return res.json({ ok: true, status: shop.kycStatus, reviewedAt: shop.kycReviewedAt });
});

app.patch('/api/admin/products/:id/moderation', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Product not found.' });
  const decision = req.body?.decision;
  if (!['hide', 'restore'].includes(decision)) return res.status(400).json({ error: 'Choose whether to hide or restore this listing.' });

  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ error: 'Product not found.' });
  product.moderationStatus = decision === 'hide' ? 'hidden' : 'visible';
  product.moderatedAt = decision === 'hide' ? new Date() : null;
  await product.save();

  return res.json({ ok: true, productId: product._id.toString(), moderationStatus: product.moderationStatus });
});

app.get('/api/products', async (req, res) => {
  await releaseExpiredReservations();
  const { q = '', category = '', town = '' } = req.query;
  if (typeof q !== 'string' || q.length > 80 || (category && !productCategories.includes(category)) || (town && !namibianTowns.includes(town))) {
    return res.status(400).json({ error: 'Invalid marketplace filters.' });
  }

  const filter = { status: 'active', isAvailable: { $ne: false }, moderationStatus: { $ne: 'hidden' } };
  if (category) filter.category = category;
  if (town) filter.town = town;
  if (q.trim()) {
    const safeQuery = q.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    filter.$or = [
      { title: { $regex: safeQuery, $options: 'i' } },
      { description: { $regex: safeQuery, $options: 'i' } }
    ];
  }

  const products = await Product.find(filter)
    .sort({ createdAt: -1 })
    .limit(60)
    .populate('shopId', 'name slug')
    .lean();

  return res.json({
    products: products.map((product) => ({
      id: product._id.toString(),
      title: product.title,
      description: product.description,
      priceNAD: product.priceNAD,
      stock: product.stock ?? null,
      category: product.category,
      town: product.town,
      imageUrl: product.imageUrl,
      shopName: product.shopId.name,
      shopSlug: product.shopId.slug
    }))
  });
});

app.get('/api/products/:id', async (req, res) => {
  await releaseExpiredReservations();
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Product not found.' });
  const product = await Product.findOne({ _id: req.params.id, status: 'active', isAvailable: { $ne: false }, moderationStatus: { $ne: 'hidden' } })
    .populate('shopId', 'name slug description town')
    .lean();

  if (!product?.shopId) return res.status(404).json({ error: 'Product not found.' });
  return res.json({
    product: {
      id: product._id.toString(),
      title: product.title,
      description: product.description,
      priceNAD: product.priceNAD,
      stock: product.stock ?? null,
      category: product.category,
      town: product.town,
      imageUrl: product.imageUrl,
      shop: product.shopId
    }
  });
});

app.get('/api/shops', async (req, res) => {
  const { q = '', town = '' } = req.query;
  if (typeof q !== 'string' || q.length > 80 || (town && !namibianTowns.includes(town))) {
    return res.status(400).json({ error: 'Invalid shop filters.' });
  }

  const filter = {};
  if (town) filter.town = town;
  if (q.trim()) {
    const safeQuery = q.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    filter.$or = [
      { name: { $regex: safeQuery, $options: 'i' } },
      { description: { $regex: safeQuery, $options: 'i' } }
    ];
  }

  const shops = await Shop.find(filter).sort({ name: 1 }).limit(100).lean();
  const shopIds = shops.map((shop) => shop._id);
  const counts = shopIds.length ? await Product.aggregate([
    { $match: { shopId: { $in: shopIds }, status: 'active', isAvailable: { $ne: false }, moderationStatus: { $ne: 'hidden' } } },
    { $sort: { createdAt: -1 } },
    { $group: { _id: '$shopId', count: { $sum: 1 }, previewImageUrl: { $first: '$imageUrl' }, previewTitle: { $first: '$title' } } }
  ]) : [];
  const productsByShop = new Map(counts.map((entry) => [entry._id.toString(), entry]));

  const reviewStats = shopIds.length ? await ShopReview.aggregate([
    { $match: { shopId: { $in: shopIds } } },
    { $group: { _id: '$shopId', reviewCount: { $sum: 1 }, averageRating: { $avg: '$rating' } } }
  ]) : [];
  const reviewsByShop = new Map(reviewStats.map((entry) => [entry._id.toString(), entry]));

  return res.json({ shops: shops.map((shop) => ({
    id: shop._id.toString(),
    name: shop.name,
    slug: shop.slug,
    businessVerified: shop.kycStatus === 'verified',
    description: shop.description,
    town: shop.town,
    productCount: productsByShop.get(shop._id.toString())?.count || 0,
    previewImageUrl: productsByShop.get(shop._id.toString())?.previewImageUrl || '',
    previewTitle: productsByShop.get(shop._id.toString())?.previewTitle || '',
    coverImageUrl: shop.coverImageUrl || '',
    averageRating: reviewsByShop.get(shop._id.toString()) ? Number((reviewsByShop.get(shop._id.toString()).averageRating).toFixed(1)) : 0,
    reviewCount: reviewsByShop.get(shop._id.toString())?.reviewCount || 0
  })) });
});

app.get('/api/shops/:slug', async (req, res) => {
  const viewer = await getSessionUser(req);
  const shop = await Shop.findOne({ slug: req.params.slug }).lean();
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  const products = await Product.find({
    shopId: shop._id,
    status: 'active',
    isAvailable: { $ne: false },
    moderationStatus: { $ne: 'hidden' }
  }).sort({ createdAt: -1 }).limit(100).lean();

  const reviews = await ShopReview.find({ shopId: shop._id }).sort({ createdAt: -1 }).populate('userId', 'name').lean();
  const reviewCount = reviews.length;
  const averageRating = reviewCount ? reviews.reduce((sum, review) => sum + review.rating, 0) / reviewCount : 0;
  const ownReview = viewer ? reviews.find((review) => review.userId && review.userId._id.toString() === viewer._id.toString()) || null : null;
  const assistantServiceConfigured = shop.assistantPlanActive && shop.assistantEnabled
    ? await isAssistantModelReady()
    : false;

  return res.json({
    shop: {
      id: shop._id.toString(),
      name: shop.name,
      slug: shop.slug,
      memberSince: shop.createdAt || null,
      businessVerified: shop.kycStatus === 'verified',
      description: shop.description,
      town: shop.town,
      coverImageUrl: shop.coverImageUrl || '',
      assistantAvailable: Boolean(shop.assistantPlanActive && shop.assistantEnabled && assistantServiceConfigured),
      averageRating: Number(averageRating.toFixed(1)),
      reviewCount
    },
    viewer: { authenticated: Boolean(viewer) },
    myReview: ownReview ? {
      id: ownReview._id.toString(),
      rating: ownReview.rating,
      comment: ownReview.comment,
      createdAt: ownReview.createdAt
    } : null,
    reviews: reviews.map((review) => ({
      id: review._id.toString(),
      rating: review.rating,
      comment: review.comment,
      createdAt: review.createdAt,
      userName: review.userId ? review.userId.name.split(' ')[0] : 'Shopper'
    })),
    products: products.map((product) => ({
      id: product._id.toString(),
      title: product.title,
      description: product.description,
      priceNAD: product.priceNAD,
      stock: product.stock ?? null,
      category: product.category,
      town: product.town,
      imageUrl: product.imageUrl
    }))
  });
});

app.post('/api/shops/:slug/assistant', shopAssistantRateLimit, async (req, res) => {
  const question = typeof req.body?.question === 'string' ? req.body.question.trim() : '';
  const requestedHistory = req.body?.history === undefined ? [] : req.body.history;
  if (!question || question.length > 500 || !Array.isArray(requestedHistory) || requestedHistory.length > 8) {
    return res.status(400).json({ error: 'Enter a question up to 500 characters.' });
  }
  const history = [];
  for (const item of requestedHistory) {
    if (!['user', 'assistant'].includes(item?.role) || typeof item.content !== 'string' || item.content.length > 500) {
      return res.status(400).json({ error: 'The conversation could not be processed.' });
    }
    history.push({ role: item.role, content: item.content });
  }

  const shop = await Shop.findOne({
    slug: req.params.slug,
    assistantPlanActive: true,
    assistantEnabled: true
  }).lean();
  if (!shop) return res.status(404).json({ error: 'This shop assistant is not available.' });
  if (!await isAssistantModelReady()) return res.status(503).json({ error: 'The local AI model is not installed or Ollama is not running.' });

  const products = await Product.find({
    shopId: shop._id,
    status: 'active',
    isAvailable: { $ne: false },
    moderationStatus: { $ne: 'hidden' }
  }).select('title description priceNAD stock category town imageUrl').sort({ createdAt: -1 }).limit(30).lean();
  const [ratingSummary = { averageRating: 0, reviewCount: 0 }] = await ShopReview.aggregate([
    { $match: { shopId: shop._id } },
    { $group: { _id: null, averageRating: { $avg: '$rating' }, reviewCount: { $sum: 1 } } }
  ]);

  try {
    const answer = await requestShopAssistantAnswer({
      shop,
      products,
      ratingSummary: { averageRating: Number((ratingSummary.averageRating || 0).toFixed(1)), reviewCount: ratingSummary.reviewCount },
      history: history.slice(-6),
      question
    });
    return res.json({ answer });
  } catch (error) {
    return res.status(error.statusCode || 502).json({ error: error.message || 'The shop assistant is temporarily unavailable.' });
  }
});

app.post('/api/shops/:slug/reviews', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to rate this shop.' });

  const shop = await Shop.findOne({ slug: req.params.slug }).select('_id');
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });

  const rating = Number(req.body?.rating);
  const comment = typeof req.body?.comment === 'string' ? req.body.comment.trim() : '';
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Choose a star rating between 1 and 5.' });
  }
  if (comment.length > 500) {
    return res.status(400).json({ error: 'Review comments must be 500 characters or fewer.' });
  }

  const review = await ShopReview.findOneAndUpdate(
    { shopId: shop._id, userId: user._id },
    { $set: { rating, comment } },
    { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true }
  );

  const allReviews = await ShopReview.find({ shopId: shop._id }).sort({ createdAt: -1 }).lean();
  const averageRating = allReviews.length ? allReviews.reduce((sum, item) => sum + item.rating, 0) / allReviews.length : 0;

  return res.status(201).json({
    review: {
      id: review._id.toString(),
      rating: review.rating,
      comment: review.comment,
      createdAt: review.createdAt
    },
    shop: {
      averageRating: Number(averageRating.toFixed(1)),
      reviewCount: allReviews.length
    }
  });
});

app.post('/api/products/:id/reports', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to report a listing.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Listing not found.' });

  const product = await Product.findOne({ _id: req.params.id, status: 'active', moderationStatus: { $ne: 'hidden' } })
    .populate('shopId', 'ownerId')
    .select('_id shopId');
  if (!product?.shopId) return res.status(404).json({ error: 'Listing not found.' });
  if (product.shopId.ownerId.toString() === user._id.toString()) return res.status(403).json({ error: 'You cannot report your own listing.' });

  const reason = req.body?.reason;
  const details = typeof req.body?.details === 'string' ? req.body.details.trim() : '';
  if (!['misleading', 'counterfeit', 'unsafe', 'prohibited', 'other'].includes(reason) || details.length > 500) {
    return res.status(400).json({ error: 'Choose a report reason and keep details under 500 characters.' });
  }

  try {
    await ListingReport.create({ productId: product._id, reporterId: user._id, reason, details });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'You have already reported this listing.' });
    throw error;
  }

  const reportCount = await ListingReport.countDocuments({ productId: product._id, status: 'pending' });
  const autoHidden = reportCount >= 3;
  if (autoHidden) {
    await Product.updateOne({ _id: product._id }, { $set: { moderationStatus: 'hidden', moderatedAt: new Date() } });
  }
  return res.status(201).json({ received: true, autoHidden, message: autoHidden ? 'Report received. This listing is temporarily hidden for review.' : 'Report received for moderator review.' });
});

app.get('/api/seller/shop', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to manage your shop.' });
  const shop = await Shop.findOne({ ownerId: user._id }).select('-kycDocumentId -kycDocumentMime -kycReviewedBy').lean();
  return res.json({
    shop,
    assistantServiceConfigured: await isAssistantModelReady(),
    assistantPurchaseSimulationAvailable: mockPaymentsEnabled
  });
});

app.get('/api/seller/shop/verification', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to manage business verification.' });
  const shop = await Shop.findOne({ ownerId: user._id }).select('name kycStatus kycBusinessName kycDocumentType kycSubmittedAt kycReviewedAt kycReviewNote').lean();
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  let storageConfigured = false;
  try { getKycEncryptionKey(); storageConfigured = true; } catch {}
  const { name, ...verification } = shop;
  return res.json({ verification, shopName: name, storageConfigured });
});

app.post('/api/seller/shop/verification', kycSubmissionRateLimit, async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to submit business verification.' });

  let encryptionKey;
  try {
    encryptionKey = getKycEncryptionKey();
  } catch (error) {
    return res.status(503).json({ error: error.message });
  }

  const shop = await Shop.findOne({ ownerId: user._id });
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  if (shop.kycStatus === 'verified') return res.status(409).json({ error: 'This business is already verified.' });
  if (shop.kycStatus === 'pending') return res.status(409).json({ error: 'Your verification is already under review.' });

  return kycDocumentUpload.single('document')(req, res, async (uploadError) => {
    if (uploadError) return next(uploadError);
    const businessName = typeof req.body?.businessName === 'string' ? req.body.businessName.trim() : '';
    const documentType = req.body?.documentType;
    if (businessName.length < 2 || businessName.length > 120 || !['business_registration', 'tax_certificate', 'other_business_document'].includes(documentType)) {
      return res.status(400).json({ error: 'Enter the registered business name and choose a document type.' });
    }
    if (!req.file) return res.status(400).json({ error: 'Upload a PDF, JPG, PNG, or WebP business document up to 10 MB.' });

    const documentMime = detectKycDocumentMime(req.file.buffer);
    if (!documentMime || documentMime !== req.file.mimetype) {
      return res.status(400).json({ error: 'The uploaded file does not match a supported document type.' });
    }

    const documentId = randomUUID();
    const documentPath = path.join(kycStorageDirectory, `${documentId}.enc`);
    try {
      await fsPromises.mkdir(kycStorageDirectory, { recursive: true, mode: 0o700 });
      await fsPromises.writeFile(documentPath, encryptKycDocument(req.file.buffer, encryptionKey), { flag: 'wx', mode: 0o600 });
      const previousDocumentId = shop.kycDocumentId;
      shop.kycStatus = 'pending';
      shop.kycBusinessName = businessName;
      shop.kycDocumentType = documentType;
      shop.kycDocumentId = documentId;
      shop.kycDocumentMime = documentMime;
      shop.kycSubmittedAt = new Date();
      shop.kycReviewedAt = null;
      shop.kycReviewedBy = null;
      shop.kycReviewNote = '';
      await shop.save();
      if (previousDocumentId && /^[a-f0-9-]{36}$/.test(previousDocumentId)) {
        await fsPromises.unlink(path.join(kycStorageDirectory, `${previousDocumentId}.enc`)).catch(() => {});
      }
      return res.status(202).json({
        verification: {
          status: shop.kycStatus,
          businessName: shop.kycBusinessName,
          documentType: shop.kycDocumentType,
          submittedAt: shop.kycSubmittedAt
        }
      });
    } catch (error) {
      await fsPromises.unlink(documentPath).catch(() => {});
      return next(error);
    }
  });
});

app.post('/api/seller/shop/assistant/simulate-purchase', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to purchase the shop assistant.' });
  if (!mockPaymentsEnabled) return res.status(503).json({ error: 'Assistant purchase simulation is only available in development.' });

  const shop = await Shop.findOneAndUpdate(
    { ownerId: user._id },
    { $set: { assistantPlanActive: true } },
    { new: true, runValidators: true }
  );
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  return res.json({
    shop: { assistantPlanActive: shop.assistantPlanActive, assistantEnabled: shop.assistantEnabled },
    assistantServiceConfigured: await isAssistantModelReady(),
    simulated: true
  });
});

app.patch('/api/seller/shop/shipping', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to update delivery settings.' });
  const values = ['localNAD', 'hubNAD', 'remoteNAD', 'freeThresholdNAD'];
  const shippingRates = {};
  for (const key of values) {
    const value = Number(req.body?.[key]);
    if (!Number.isFinite(value) || value < 0 || value > 1000000) {
      return res.status(400).json({ error: 'Enter valid non-negative delivery rates and threshold.' });
    }
    shippingRates[key] = roundNAD(value);
  }

  const rawAutoApproval = req.body?.autoApprovalEnabled;
  const autoApprovalEnabled = typeof rawAutoApproval === 'boolean' ? rawAutoApproval : Boolean(rawAutoApproval === 'true');

  const shop = await Shop.findOneAndUpdate({ ownerId: user._id }, { $set: { shippingRates, autoApprovalEnabled } }, { new: true, runValidators: true });
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  return res.json({ shippingRates: shop.shippingRates, autoApprovalEnabled: shop.autoApprovalEnabled });
});

app.patch('/api/seller/shop/assistant', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to manage your shop assistant.' });

  const assistantEnabled = req.body?.assistantEnabled;
  if (typeof assistantEnabled !== 'boolean') {
    return res.status(400).json({ error: 'Choose whether the shop assistant should be shown.' });
  }

  const shop = await Shop.findOne({ ownerId: user._id });
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  if (assistantEnabled && !shop.assistantPlanActive) {
    return res.status(402).json({ error: 'Purchase the shop assistant add-on before turning it on.' });
  }

  shop.assistantEnabled = assistantEnabled;
  await shop.save();
  return res.json({
    assistantEnabled: shop.assistantEnabled,
    assistantPlanActive: shop.assistantPlanActive,
    assistantServiceConfigured: await isAssistantModelReady()
  });
});

app.post('/api/seller/shop', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to create a shop.' });

  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const description = typeof req.body?.description === 'string' ? req.body.description.trim() : '';
  const town = req.body?.town;
  if (!name || name.length > 80 || !description || description.length > 500 || !namibianTowns.includes(town)) {
    return res.status(400).json({ error: 'Enter a shop name, a short description, and a valid town.' });
  }

  const slug = `${name.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50) || 'shop'}-${randomBytes(3).toString('hex')}`;
  try {
    const shop = await Shop.create({ ownerId: user._id, name, description, town, slug });
    return res.status(201).json({ shop: { id: shop._id.toString(), name: shop.name, description: shop.description, town: shop.town, slug: shop.slug } });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'You already have a shop. Refresh this page to manage it.' });
    throw error;
  }
});

app.post('/api/seller/products/upload', sellerUploadRateLimit, async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to upload product images.' });
  const shop = await Shop.findOne({ ownerId: user._id }).select('_id');
  if (!shop) return res.status(409).json({ error: 'Create your storefront before uploading product images.' });
  req.uploadShop = shop;
  return next();
}, imageUpload.single('file'), async (req, res) => {
  if (!req.file || !hasValidImageSignature(req.file)) {
    return res.status(400).json({ error: 'Upload a valid JPG, PNG, or WebP image.' });
  }

  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  const uploadPreset = process.env.CLOUDINARY_UPLOAD_PRESET;
  if (!cloudName || !apiKey || !apiSecret || !uploadPreset) {
    return res.status(503).json({ error: 'Cloudinary uploads are not configured yet.' });
  }

  const kind = req.body?.kind || 'product';
  if (!['product', 'shop-cover'].includes(kind)) return res.status(400).json({ error: 'Invalid image upload type.' });
  cloudinary.config({ cloud_name: cloudName, api_key: apiKey, api_secret: apiSecret, secure: true });
  const result = await new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream({
      folder: `z/${kind === 'shop-cover' ? 'shops' : 'products'}/${req.uploadShop._id}`,
      public_id: randomBytes(16).toString('hex'),
      allowed_formats: 'jpg,png,webp',
      transformation: { width: 2000, height: 2000, crop: 'limit', flags: 'force_strip' },
      upload_preset: uploadPreset
    }, (error, uploaded) => error ? reject(error) : resolve(uploaded));
    stream.end(req.file.buffer);
  });
  if (typeof result.secure_url !== 'string') throw new Error('Cloudinary did not return a secure image URL.');
  return res.status(201).json({ imageUrl: result.secure_url });
});

app.patch('/api/seller/shop/cover', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to update your shop photo.' });
  const coverImageUrl = typeof req.body?.coverImageUrl === 'string' ? req.body.coverImageUrl.trim() : '';
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const expectedPrefix = cloudName ? `https://res.cloudinary.com/${cloudName}/image/upload/` : '';
  if (!expectedPrefix || !coverImageUrl.startsWith(expectedPrefix) || coverImageUrl.length > 2048) {
    return res.status(400).json({ error: 'Upload a storefront photo to Z through Cloudinary first.' });
  }

  const shop = await Shop.findOneAndUpdate({ ownerId: user._id }, { $set: { coverImageUrl } }, { new: true, runValidators: true });
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  return res.json({ coverImageUrl: shop.coverImageUrl });
});

app.get('/api/seller/products', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to manage listings.' });
  const shop = await Shop.findOne({ ownerId: user._id });
  if (!shop) return res.json({ products: [] });
  const products = await Product.find({ shopId: shop._id }).sort({ createdAt: -1 }).lean();
  return res.json({ products: products.map((product) => ({ ...product, id: product._id.toString() })) });
});

app.post('/api/seller/products', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to publish a listing.' });
  const shop = await Shop.findOne({ ownerId: user._id });
  if (!shop) return res.status(409).json({ error: 'Create your storefront before adding products.' });

  const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
  const description = typeof req.body?.description === 'string' ? req.body.description.trim() : '';
  const priceNAD = Number(req.body?.priceNAD);
  const stock = Number(req.body?.stock);
  const category = req.body?.category;
  const imageUrls = normalizeImageUrls(req.body?.imageUrls || req.body?.imageUrl || []);
  const imageUrl = imageUrls[0] || '';
  const imageIsValid = imageUrls.length === 0 || imageUrls.every((url) => validateImageUrl(url));

  if (!title || title.length > 100 || !description || description.length > 1500 || !Number.isFinite(priceNAD) || priceNAD < 0.01 || priceNAD > 10000000 || !Number.isInteger(stock) || stock < 0 || stock > 100000 || !productCategories.includes(category) || !imageIsValid) {
    return res.status(400).json({ error: 'Check the product details, price, stock, category, and image URL.' });
  }

  const product = await Product.create({ shopId: shop._id, title, description, priceNAD, stock, isAvailable: stock > 0, category, town: shop.town, imageUrl, imageUrls });
  return res.status(201).json({ product: { id: product._id.toString(), title: product.title, priceNAD: product.priceNAD, stock: product.stock, category: product.category } });
});

app.patch('/api/seller/products/:id', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to update listings.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Listing not found.' });

  const shop = await Shop.findOne({ ownerId: user._id });
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  const product = await Product.findOne({ _id: req.params.id, shopId: shop._id });
  if (!product) return res.status(404).json({ error: 'Listing not found.' });

  let updates;
  if (req.body?.status !== undefined) {
    if (!['active', 'archived'].includes(req.body.status)) return res.status(400).json({ error: 'Invalid listing status.' });
    updates = { status: req.body.status };
  } else {
    const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
    const description = typeof req.body?.description === 'string' ? req.body.description.trim() : '';
    const priceNAD = Number(req.body?.priceNAD);
    const stock = Number(req.body?.stock);
    const category = req.body?.category;
    const imageUrls = normalizeImageUrls(req.body?.imageUrls || req.body?.imageUrl || []);
    const imageUrl = imageUrls[0] || '';
    const imageIsValid = imageUrls.length === 0 || imageUrls.every((url) => validateImageUrl(url));

    if (!title || title.length > 100 || !description || description.length > 1500 || !Number.isFinite(priceNAD) || priceNAD < 0.01 || priceNAD > 10000000 || !Number.isInteger(stock) || stock < 0 || stock > 100000 || !productCategories.includes(category) || !imageIsValid) {
      return res.status(400).json({ error: 'Check the product details, price, stock, category, and image URL.' });
    }

    updates = { title, description, priceNAD, stock, isAvailable: stock > 0, category, imageUrl, imageUrls };
  }

  const updated = await Product.findByIdAndUpdate(product._id, { $set: updates }, { new: true, runValidators: true }).lean();
  return res.json({ product: { id: updated._id.toString(), title: updated.title, description: updated.description, priceNAD: updated.priceNAD, stock: updated.stock, category: updated.category, imageUrl: updated.imageUrl, imageUrls: updated.imageUrls || [], status: updated.status } });
});

app.delete('/api/seller/products/:id', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to delete listings.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Listing not found.' });

  const shop = await Shop.findOne({ ownerId: user._id });
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  const product = await Product.findOneAndDelete({ _id: req.params.id, shopId: shop._id });
  if (!product) return res.status(404).json({ error: 'Listing not found.' });
  return res.json({ ok: true });
});

app.get(['/', '/marketplace'], (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'client', 'marketplace.html'));
});

app.get('/login', async (req, res) => {
  if (await getSessionUser(req)) return res.redirect('/dashboard');
  return res.sendFile(path.join(__dirname, '..', 'client', 'home.html'));
});

app.get('/reset-password', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'reset-password.html'));
});

app.get('/health', (req, res) => {
  const isReady = mongoose.connection.readyState === 1;
  return res.status(isReady ? 200 : 503).json({ status: isReady ? 'ok' : 'unavailable' });
});

app.use('/api', (req, res) => {
  return res.status(404).json({ error: 'API endpoint not found.' });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof multer.MulterError) {
    const message = error.code === 'LIMIT_FILE_SIZE'
      ? 'Image files must be 5 MB or smaller.'
      : 'Upload one image file at a time.';
    return res.status(400).json({ error: message });
  }
  const statusCode = Number.isInteger(error.statusCode) ? error.statusCode : Number.isInteger(error.status) ? error.status : 500;
  if (statusCode >= 500) console.error('Unhandled request error:', error);
  const message = statusCode >= 500
    ? 'Z is temporarily unavailable. Please try again.'
    : statusCode === 400 ? 'Invalid request.' : error.message;
  return res.status(statusCode).json({ error: message });
});

async function startServer() {
  assertProductionPaymentConfiguration();
  assertProductionAdminConfiguration();
  if (!process.env.MONGODB_URI) {
    throw new Error('Missing MONGODB_URI. Add it to server/.env before starting Z.');
  }

  await mongoose.connect(process.env.MONGODB_URI);
  await Promise.all([User.init(), Session.init(), PasswordReset.init(), Shop.init(), Product.init(), Order.init(), ListingReport.init(), SupportRequest.init()]);
  const reservationSweep = setInterval(() => {
    releaseExpiredReservations().catch((error) => console.error('Reservation cleanup failed:', error.message));
  }, 60 * 1000);
  reservationSweep.unref();
  await advancePayoutLifecycle();
  const payoutSweep = setInterval(() => {
    advancePayoutLifecycle().catch((error) => console.error('Payout simulation failed:', error.message));
  }, payoutSweepIntervalMs);
  payoutSweep.unref();

  const port = process.env.PORT || 3001;
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
    console.log('MongoDB connected.');
  });
}

if (require.main === module) {
  startServer().catch((error) => {
    console.error(`Server startup failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = {
  canCancelOrder,
  resolveSellerApprovalState,
  getBuyerDisplayName,
  normalizeSupportRequest,
  normalizePasswordResetInput,
  isAdminUser,
  validateImageUrl,
  hasValidImageSignature,
  resolvePayoutStatus,
  assertProductionPaymentConfiguration,
  assertProductionAdminConfiguration
};