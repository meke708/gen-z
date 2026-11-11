const express = require('express');
const path = require('path');
const os = require('os');
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
const { PDFParse } = require('pdf-parse');
const { createPaymentAdapter } = require('./payment-adapter');
const { isAssistantModelReady, requestShopAssistantAnswer } = require('./shop-assistant');
const { decryptKycDocument, detectKycDocumentMime, encryptKycDocument, getKycEncryptionKey, isKycStorageConfigured } = require('./kyc-storage');
const { resolveLoginNetwork } = require('./login-activity');
const { getProductBasicDataIssues, getProductReviewDecision } = require('./product-review');
const { getServerDiagnostics } = require('./runtime-diagnostics');
const { listAllowedTests, runAllowedTest, runAllAllowedTests } = require('./approved-test-runner');
const { DEFAULT_LOGIN_WALLPAPER, normalizeLoginWallpaper } = require('./login-wallpaper');
const { normalizeBankPayoutAccount, normalizePayoutRequestAmount } = require('./payout-settings');
const { getStatementSigningKey, signStatement, verifyStatement } = require('./statement-signature');
const { getStatementPdfChecks } = require('./statement-pdf');
const { getDeveloperApiUsageCounters } = require('./developer-api-usage');
const { verifyDeveloperTestPassword } = require('./developer-test-access');
const {
  createDeveloperCredentials,
  hashDeveloperToken,
  isValidDeveloperToken,
  normalizeDeveloperAppName
} = require('./developer-api');
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
const promotionPriceNAD = 50;
const promotionDurationDays = 7;
const assistantPriceNAD = 50;
const paymentAdapter = createPaymentAdapter(process.env.PAYMENT_MODE || 'mock');
const developerTestSessions = new Map();
const developerTestSessionDurationMs = 30 * 60 * 1000;
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Try again in 15 minutes.' }
});
const cartWriteRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Your cart is updating too often. Please wait a moment and try again.' }
});
const wishlistWriteRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Your wishlist is updating too often. Please wait a moment and try again.' }
});
const promotionWriteRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Promotion requests are limited. Please try again later.' }
});
const sellerPayoutRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Payout settings and requests are limited. Try again in an hour.' }
});
const sellerStatementRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Statement generation is limited. Try again in an hour.' }
});
const developerAppRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Developer app changes are limited. Try again in an hour.' }
});
const statementApiRateLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Statement API rate limit exceeded. Try again in a minute.' }
});
const developerTestUnlockRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many test-client password attempts. Try again in 15 minutes.' }
});
const adminStatementRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Statement verification uploads are limited. Try again in an hour.' }
});
const promotionEngagementRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Promotion tracking requests are limited. Please try again later.' }
});
const supportRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'You have sent several support requests. Try again in an hour.' }
});
const listingReportRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many listing reports. Please try again later.' }
});
const suspensionAppealRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 3,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many appeal submissions. Please try again in an hour.' }
});
const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many password reset attempts. Try again in an hour.' }
});
const emailVerificationRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'You have requested several verification emails. Try again in an hour.' }
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
const commandTestRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Test runs are limited. Please try again later.' }
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
const statementPdfUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1, fields: 1, fieldSize: 64 }
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
  role: { type: String, enum: ['customer', 'moderator', 'sandbox'], default: 'customer', index: true },
  emailVerified: { type: Boolean, default: false },
  isSuspended: { type: Boolean, default: false, index: true },
  walletBalanceNAD: { type: Number, default: 0, min: 0 },
  payoutBankAccount: {
    bankName: { type: String, trim: true, maxlength: 80 },
    accountName: { type: String, trim: true, maxlength: 80 },
    accountLast4: { type: String, match: /^\d{4}$/ }
  },
  dismissedListingReportCount: { type: Number, default: 0, min: 0 },
  cartItems: {
    type: [{
      _id: false,
      productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
      quantity: { type: Number, required: true, min: 1, max: 99 }
    }],
    default: []
  },
  wishlistProductIds: {
    type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
    default: []
  },
  phone: { type: String, trim: true, maxlength: 24, default: '' },
  town: { type: String, trim: true, default: '' },
  referralCode: { type: String, unique: true, sparse: true, index: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  salt: { type: String, required: true },
  passwordHash: { type: String, required: true }
}, { timestamps: true });
const walletTransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  reference: { type: String, required: true, unique: true },
  type: { type: String, enum: ['seller_credit', 'purchase_debit', 'purchase_refund'], required: true },
  amountNAD: { type: Number, required: true, min: 0 },
  balanceAfterNAD: { type: Number, required: true, min: 0 },
  orderNumber: { type: String, required: true },
  description: { type: String, required: true, maxlength: 200 }
}, { timestamps: true });
walletTransactionSchema.index({ userId: 1, createdAt: -1 });
const simulatedPayoutRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true, index: true },
  amountNAD: { type: Number, required: true, min: 0.01 },
  status: { type: String, enum: ['simulated'], default: 'simulated' },
  mode: { type: String, enum: ['simulated'], default: 'simulated' },
  destination: {
    bankName: { type: String, required: true, maxlength: 80 },
    accountName: { type: String, required: true, maxlength: 80 },
    accountLast4: { type: String, required: true, match: /^\d{4}$/ }
  }
}, { timestamps: true });
simulatedPayoutRequestSchema.index({ userId: 1, createdAt: -1 });
const sellerStatementSchema = new mongoose.Schema({
  statementId: { type: String, required: true, unique: true, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  snapshot: { type: mongoose.Schema.Types.Mixed, required: true },
  signature: { type: String, required: true, match: /^[a-f\d]{64}$/i }
}, { timestamps: true });
const developerApplicationSchema = new mongoose.Schema({
  appId: { type: String, required: true, unique: true, index: true },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  name: { type: String, required: true, trim: true, maxlength: 80 },
  tokenHash: { type: String, required: true, unique: true },
  tokenLast4: { type: String, required: true, match: /^[A-Za-z0-9_-]{4}$/ },
  revokedAt: { type: Date, default: null, index: true },
  lastUsedAt: { type: Date, default: null }
}, { timestamps: true });
const developerApiUsageSchema = new mongoose.Schema({
  day: { type: Date, required: true },
  endpoint: { type: String, enum: ['reference', 'pdf'], required: true },
  appId: { type: String, default: null },
  requests: { type: Number, default: 0, min: 0 },
  successes: { type: Number, default: 0, min: 0 },
  verified: { type: Number, default: 0, min: 0 },
  mismatched: { type: Number, default: 0, min: 0 },
  clientErrors: { type: Number, default: 0, min: 0 },
  serverErrors: { type: Number, default: 0, min: 0 },
  totalDurationMs: { type: Number, default: 0, min: 0 },
  expiresAt: { type: Date, required: true }
}, { versionKey: false });
developerApiUsageSchema.index({ day: 1, endpoint: 1, appId: 1 }, { unique: true });
developerApiUsageSchema.index({ appId: 1, day: -1 });
developerApiUsageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const sessionSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt: { type: Date, required: true, expires: 0 }
}, { timestamps: true });
sessionSchema.index({ userId: 1, createdAt: -1 });
const loginActivitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  device: { type: String, required: true, maxlength: 80 },
  client_ip: { type: String, default: '', maxlength: 45 },
  country_code: { type: String, default: '', maxlength: 2 },
  city: { type: String, default: '', maxlength: 120 },
  isp_provider: { type: String, default: '', maxlength: 200 },
  readAt: { type: Date, default: null },
  expiresAt: { type: Date, required: true, expires: 0 }
}, { timestamps: true });
loginActivitySchema.index({ userId: 1, createdAt: -1 });
const passwordResetSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  expiresAt: { type: Date, required: true, expires: 0 }
}, { timestamps: true });
const emailVerificationSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
  expiresAt: { type: Date, required: true, expires: 0 }
}, { timestamps: true });
const shopSchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  sellerSuspended: { type: Boolean, default: false, index: true },
  sellerRestrictionStatus: { type: String, enum: ['active', 'temp_hold', 'banned'], default: 'active', index: true },
  sellerRestrictedUntil: { type: Date, default: null, index: true },
  sellerRestrictionLastTriggeredAt: { type: Date, default: null },
  sellerRestrictionReason: { type: String, default: '', trim: true, maxlength: 500 },
  name: { type: String, required: true, trim: true, maxlength: 80 },
  nameKey: { type: String, select: false },
  slug: { type: String, required: true, unique: true },
  approvalStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'approved', index: true },
  approvalNote: { type: String, trim: true, maxlength: 500, default: '' },
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
  assistantPlanPaidAt: { type: Date, default: null },
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
shopSchema.index({ nameKey: 1 }, { unique: true, partialFilterExpression: { nameKey: { $type: 'string' } } });
const productSchema = new mongoose.Schema({
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true, index: true },
  duplicateKey: { type: String, select: false },
  title: { type: String, trim: true, maxlength: 100, default: '' },
  description: { type: String, trim: true, maxlength: 1500, default: '' },
  priceNAD: { type: Number, min: 0, default: 0 },
  stock: { type: Number, min: 0, max: 100000, default: null },
  isAvailable: { type: Boolean, default: true },
  category: { type: String, default: '' },
  town: { type: String, required: true },
  imageUrl: { type: String, default: '' },
  imageUrls: { type: [String], default: [] },
  status: { type: String, enum: ['active', 'archived'], default: 'active' },
  reviewStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'approved', index: true },
  reviewReasons: { type: [String], default: [] },
  moderationStatus: { type: String, enum: ['visible', 'hidden'], default: 'visible' },
  moderationSource: { type: String, enum: ['moderator', 'report_threshold', null], default: null },
  moderatedAt: { type: Date, default: null }
}, { timestamps: true });
productSchema.index(
  { shopId: 1, duplicateKey: 1 },
  { unique: true, partialFilterExpression: { duplicateKey: { $type: 'string' } } }
);
const promotionCampaignSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true, index: true },
  amountNAD: { type: Number, required: true, min: 0.01 },
  durationDays: { type: Number, required: true, min: 1 },
  status: { type: String, enum: ['pending', 'active', 'expired', 'cancelled'], default: 'pending', index: true },
  paymentReference: { type: String, required: true, unique: true },
  paymentExpiresAt: { type: Date, required: true },
  paymentMethod: { type: String, enum: ['card', 'wallet', null], default: null },
  walletUsedNAD: { type: Number, min: 0, default: 0 },
  cardDueNAD: { type: Number, min: 0, default: 0 },
  paidAt: { type: Date, default: null },
  startsAt: { type: Date, default: null },
  expiresAt: { type: Date, default: null }
}, { timestamps: true });
const promotionEngagementSchema = new mongoose.Schema({
  campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'PromotionCampaign', required: true },
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true },
  eventType: { type: String, enum: ['impression', 'click'], required: true },
  placement: { type: String, enum: ['marketplace', 'dashboard'], required: true },
  date: { type: Date, required: true },
  visitorHash: { type: String, required: true }
}, { versionKey: false });
promotionEngagementSchema.index(
  { campaignId: 1, placement: 1, eventType: 1, date: 1, visitorHash: 1 },
  { unique: true }
);
promotionEngagementSchema.index({ shopId: 1, date: 1 });
promotionCampaignSchema.index(
  { productId: 1 },
  { name: 'active_promotion_product_unique', unique: true, partialFilterExpression: { status: 'active' } }
);
const listingReportSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  reporterId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  reviewedAt: { type: Date, default: null },
  reason: { type: String, enum: ['misleading', 'counterfeit', 'unsafe', 'prohibited', 'other'], required: true },
  details: { type: String, default: '', trim: true, maxlength: 500 },
  credibilityPoints: { type: Number, default: 5, min: 0, max: 25 },
  verifiedBuyer: { type: Boolean, default: false },
  sellerReporter: { type: Boolean, default: false },
  status: { type: String, enum: ['pending', 'dismissed', 'actioned'], default: 'pending', index: true }
}, { timestamps: true });
listingReportSchema.index({ productId: 1, reporterId: 1 }, { unique: true });
listingReportSchema.index({ reporterId: 1, createdAt: -1 });
listingReportSchema.index({ reviewedBy: 1, reviewedAt: -1 });
const listingThresholdEventSchema = new mongoose.Schema({
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true, index: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  triggeredAt: { type: Date, required: true, default: Date.now }
}, { versionKey: false });
listingThresholdEventSchema.index({ shopId: 1, triggeredAt: -1 });
listingThresholdEventSchema.index({ shopId: 1, productId: 1, triggeredAt: 1 }, { unique: true });
listingThresholdEventSchema.index({ triggeredAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });
const moderationAuditSchema = new mongoose.Schema({
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  action: { type: String, enum: [
    'listing_report_dismissed', 'listing_hidden', 'listing_restored',
    'account_suspended', 'account_reactivated',
    'seller_access_suspended', 'seller_access_reactivated',
    'seller_access_auto_held', 'seller_access_auto_released', 'seller_access_banned'
  ], required: true, index: true },
  actorType: { type: String, enum: ['admin', 'moderator', 'system'], default: 'moderator', required: true },
  targetType: { type: String, enum: ['listing_report', 'listing', 'account'], required: true },
  targetId: { type: String, required: true, maxlength: 100 },
  targetLabel: { type: String, default: '', trim: true, maxlength: 200 },
  details: { type: String, default: '', trim: true, maxlength: 500 }
}, { timestamps: true });
moderationAuditSchema.index({ createdAt: -1 });
moderationAuditSchema.index({ targetType: 1, targetId: 1, createdAt: -1 });
moderationAuditSchema.index({ actorId: 1, createdAt: -1 });
const shopReviewSchema = new mongoose.Schema({
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String, default: '', trim: true, maxlength: 500 }
}, { timestamps: true });
shopReviewSchema.index({ shopId: 1, userId: 1 }, { unique: true });
shopReviewSchema.index({ userId: 1, createdAt: -1 });
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
  commissionRate: { type: Number, min: 0, max: 1 },
  approvalStatus: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending', index: true },
  fulfillmentStatus: { type: String, enum: ['awaiting_payment', 'processing', 'shipped', 'delivered', 'disputed'], default: 'awaiting_payment' },
  payoutStatus: { type: String, enum: ['held', 'eligible', 'paid', 'disputed'], default: 'held' },
  trackingReference: { type: String, default: '' },
  deliveredAt: { type: Date, default: null },
  payoutEligibleAt: { type: Date, default: null },
  walletCreditedAt: { type: Date, default: null },
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
  commissionRate: { type: Number, min: 0, max: 1 },
  totalNAD: { type: Number, required: true, min: 0 },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'expired', 'cancelled'], default: 'pending', index: true },
  paymentMethod: { type: String, enum: ['card', 'wallet'], default: 'card' },
  walletUsedNAD: { type: Number, default: 0, min: 0 },
  cardDueNAD: { type: Number, default: 0, min: 0 },
  paymentMode: { type: String, enum: ['mock'], default: 'mock' },
  paymentReference: { type: String, default: '' },
  reservationExpiresAt: { type: Date, required: true, index: true },
  reservationsReleasedAt: { type: Date, default: null },
  paidAt: { type: Date, default: null }
}, { timestamps: true });
const supportRequestSchema = new mongoose.Schema({
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', default: null, index: true },
  orderNumber: { type: String, default: '', index: true },
  buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  category: { type: String, enum: ['general', 'financial', 'identity'], default: 'general', index: true },
  topic: { type: String, enum: [
    'delivery', 'refund', 'return', 'item_issue', 'other',
    'listing_storefront', 'platform_navigation', 'delayed_payout', 'banking_details',
    'fee_commission', 'transaction_failure', 'rejected_business_application',
    'document_upload_failure', 'account_reinstatement'
  ], required: true },
  message: { type: String, required: true, trim: true, maxlength: 1500 },
  status: { type: String, enum: ['open', 'in_review', 'resolved'], default: 'open', index: true },
  adminResponse: { type: String, default: '', trim: true, maxlength: 1000 }
}, { timestamps: true });
supportRequestSchema.index({ status: 1, createdAt: 1 });
const supportNotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  supportRequestId: { type: mongoose.Schema.Types.ObjectId, ref: 'SupportRequest', required: true, index: true },
  readAt: { type: Date, default: null }
}, { timestamps: true });
supportNotificationSchema.index({ userId: 1, supportRequestId: 1 }, { unique: true });
const sellerNotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['promotion_cancelled'], required: true },
  promotionId: { type: mongoose.Schema.Types.ObjectId, ref: 'PromotionCampaign', required: true },
  title: { type: String, required: true, trim: true, maxlength: 120 },
  message: { type: String, required: true, trim: true, maxlength: 500 },
  readAt: { type: Date, default: null }
}, { timestamps: true });
sellerNotificationSchema.index({ userId: 1, promotionId: 1, type: 1 }, { unique: true });
const accountNotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true, trim: true, maxlength: 120 },
  message: { type: String, required: true, trim: true, maxlength: 1000 },
  destination: { type: String, enum: ['account', 'seller', 'both'], default: 'both', index: true },
  accountReadAt: { type: Date, default: null },
  sellerReadAt: { type: Date, default: null },
  readAt: { type: Date, default: null }
}, { timestamps: true });
accountNotificationSchema.index({ userId: 1, createdAt: -1 });
const walletReconciliationAlertSchema = new mongoose.Schema({
  accountId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  status: { type: String, enum: ['open', 'resolved'], required: true, default: 'open' },
  accountBalanceNAD: { type: Number, required: true },
  ledgerBalanceNAD: { type: Number, required: true },
  expectedBalanceNAD: { type: Number, required: true },
  matchedBalanceNAD: { type: Number, required: true },
  differenceNAD: { type: Number, required: true },
  ledgerIntegrityDifferenceNAD: { type: Number, required: true },
  transactionCount: { type: Number, required: true },
  generation: { type: Number, default: 0 },
  notifiedGeneration: { type: Number, default: null },
  openedAt: { type: Date, required: true },
  resolvedAt: { type: Date, default: null },
  lastCheckedAt: { type: Date, required: true }
}, { timestamps: true });
const suspensionAppealSchema = new mongoose.Schema({
  accountEmail: { type: String, required: true, trim: true, lowercase: true, maxlength: 254, index: true },
  activeEmailKey: { type: String, default: undefined },
  reason: { type: String, required: true, trim: true, maxlength: 2000 },
  referenceId: { type: String, default: '', trim: true, maxlength: 100 },
  status: { type: String, enum: ['open', 'in_review', 'resolved'], default: 'open', index: true }
}, { timestamps: true });
suspensionAppealSchema.index({ status: 1, createdAt: 1 });
suspensionAppealSchema.index({ activeEmailKey: 1 }, { unique: true, sparse: true });
const suspensionAppealAccessSchema = new mongoose.Schema({
  accountEmail: { type: String, required: true, unique: true, trim: true, lowercase: true },
  verificationTokenHash: { type: String, default: null },
  expiresAt: { type: Date, required: true, expires: 0 }
}, { timestamps: true });
const platformSettingSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  commissionRate: { type: Number, required: true, min: 0, max: 1 }
}, { timestamps: true });
const loginWallpaperSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true, default: 'login' },
  productId: { type: mongoose.Schema.Types.ObjectId, default: null },
  productIds: { type: [{ type: mongoose.Schema.Types.ObjectId }], default: undefined },
  rotatePromotions: { type: Boolean, default: undefined },
  topLine: { type: String, required: true, maxlength: 120 },
  headline: { type: String, required: true, maxlength: 90 },
  headlineAccent: { type: String, required: true, maxlength: 90 },
  description: { type: String, default: '', maxlength: 280 },
  caption: { type: String, default: '', maxlength: 160 },
  footerLeft: { type: String, default: '', maxlength: 40 },
  footerRight: { type: String, default: '', maxlength: 40 },
  imageX: { type: Number, required: true, min: 0, max: 100 },
  imageY: { type: Number, required: true, min: 0, max: 100 },
  overlay: { type: Number, required: true, min: 0, max: 0.6 }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const LoginActivity = mongoose.model('LoginActivity', loginActivitySchema);
const PasswordReset = mongoose.model('PasswordReset', passwordResetSchema);
const EmailVerification = mongoose.model('EmailVerification', emailVerificationSchema);
const Shop = mongoose.model('Shop', shopSchema);
const Product = mongoose.model('Product', productSchema);
const PromotionCampaign = mongoose.model('PromotionCampaign', promotionCampaignSchema);
const PromotionEngagement = mongoose.model('PromotionEngagement', promotionEngagementSchema);
const ListingReport = mongoose.model('ListingReport', listingReportSchema);
const ListingThresholdEvent = mongoose.model('ListingThresholdEvent', listingThresholdEventSchema);
const ModerationAudit = mongoose.model('ModerationAudit', moderationAuditSchema);
const ShopReview = mongoose.model('ShopReview', shopReviewSchema);
const Order = mongoose.model('Order', orderSchema);
const WalletTransaction = mongoose.model('WalletTransaction', walletTransactionSchema);
const SimulatedPayoutRequest = mongoose.model('SimulatedPayoutRequest', simulatedPayoutRequestSchema);
const SellerStatement = mongoose.model('SellerStatement', sellerStatementSchema);
const DeveloperApplication = mongoose.model('DeveloperApplication', developerApplicationSchema);
const DeveloperApiUsage = mongoose.model('DeveloperApiUsage', developerApiUsageSchema);
const SupportRequest = mongoose.model('SupportRequest', supportRequestSchema);
const SupportNotification = mongoose.model('SupportNotification', supportNotificationSchema);
const SellerNotification = mongoose.model('SellerNotification', sellerNotificationSchema);
const AccountNotification = mongoose.model('AccountNotification', accountNotificationSchema);
const WalletReconciliationAlert = mongoose.model('WalletReconciliationAlert', walletReconciliationAlertSchema);
const SuspensionAppeal = mongoose.model('SuspensionAppeal', suspensionAppealSchema);
const SuspensionAppealAccess = mongoose.model('SuspensionAppealAccess', suspensionAppealAccessSchema);
const PlatformSetting = mongoose.model('PlatformSetting', platformSettingSchema);
const LoginWallpaper = mongoose.model('LoginWallpaper', loginWallpaperSchema);
const productCategories = [
  'Art & Crafts', 'Beauty', 'Electronics', 'Fashion', 'Food', 'Home',
  'Clothing', 'Shoes', 'Books', 'Furniture', 'Homeware',
  'Health & Medicines (NMRC)', 'Telecom / Wi-Fi / Bluetooth (CRAN)',
  'Food & Agriculture', 'Second-hand clothes'
];
const namibianTowns = ['Windhoek', 'Swakopmund', 'Walvis Bay', 'Oshakati', 'Rundu', 'Otjiwarongo', 'Other'];
const hubTowns = new Set(['Windhoek', 'Swakopmund', 'Walvis Bay', 'Oshakati', 'Rundu', 'Otjiwarongo']);
const commissionRate = Number(process.env.PLATFORM_COMMISSION_RATE || 0.1);
if (!Number.isFinite(commissionRate) || commissionRate < 0 || commissionRate > 1) {
  throw new Error('PLATFORM_COMMISSION_RATE must be between 0 and 1.');
}
const reservationDurationMs = Number(process.env.ORDER_RESERVATION_MINUTES || 15) * 60 * 1000;
const payoutHoldDurationMs = Number(process.env.PAYOUT_HOLD_HOURS || 72) * 60 * 60 * 1000;
if (!Number.isFinite(payoutHoldDurationMs) || payoutHoldDurationMs <= 0) {
  throw new Error('PAYOUT_HOLD_HOURS must be a positive number.');
}
const simulatedPayoutsEnabled = paymentAdapter.mode === 'mock' && process.env.NODE_ENV !== 'production' && process.env.SIMULATE_PAYOUTS !== 'false';
const payoutSweepSeconds = Number(process.env.PAYOUT_SWEEP_SECONDS || (simulatedPayoutsEnabled ? 1 : 60));
if (!Number.isFinite(payoutSweepSeconds) || payoutSweepSeconds < 1 || payoutSweepSeconds > 3600) {
  throw new Error('PAYOUT_SWEEP_SECONDS must be between 1 and 3600.');
}
const payoutSweepIntervalMs = payoutSweepSeconds * 1000;
const mockPaymentsRequested = paymentAdapter.mode === 'mock' && process.env.MOCK_PAYMENTS_ENABLED !== 'false';
const allowMockPaymentsInProduction = process.env.ALLOW_MOCK_PAYMENTS_IN_PRODUCTION === 'true';
const mockPaymentsEnabled = mockPaymentsRequested && (process.env.NODE_ENV !== 'production' || allowMockPaymentsInProduction);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      connectSrc: ["'self'"],
      frameSrc: ["'self'", 'https://www.google.com'],
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

app.use('/sell', async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user || isEmailVerified(user)) return next();
  return res.redirect(`/verify-email?returnTo=${encodeURIComponent(req.originalUrl)}`);
});

app.get('/sell', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.findOne({ ownerId: user._id }).select('sellerSuspended').lean();
  if (shop?.sellerSuspended) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  return res.redirect(shop ? '/sell/dashboard' : '/sell/setup');
});

app.get('/sell/setup', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.findOne({ ownerId: user._id });
  if (shop?.sellerSuspended) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  if (shop) return res.redirect('/sell/dashboard');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell-setup.html'));
});

app.get('/sell/dashboard', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.findOne({ ownerId: user._id });
  if (shop?.sellerSuspended) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  if (!shop) return res.redirect('/sell/setup');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell.html'));
});

app.get('/sell/orders', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.findOne({ ownerId: user._id });
  if (shop?.sellerSuspended) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  if (!shop) return res.redirect('/sell/setup');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell.html'));
});

app.get('/sell/listings', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.findOne({ ownerId: user._id });
  if (shop?.sellerSuspended) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  if (!shop) return res.redirect('/sell/setup');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell.html'));
});

app.get('/sell/promotions', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.findOne({ ownerId: user._id });
  if (shop?.sellerSuspended) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  if (!shop) return res.redirect('/sell/setup');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell.html'));
});

app.get('/sell/notifications', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.findOne({ ownerId: user._id });
  if (shop?.sellerSuspended) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  if (!shop) return res.redirect('/sell/setup');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell.html'));
});

app.get('/sell/transactions', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.findOne({ ownerId: user._id });
  if (shop?.sellerSuspended) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  if (!shop) return res.redirect('/sell/setup');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell-transactions.html'));
});

app.get('/statement-verification', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'statement-verification.html'));
});

app.get('/developers', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'developer-portal.html'));
});

function getDeveloperTestSession(req) {
  const token = req.headers.cookie?.split(';')
    .map((item) => item.trim())
    .find((item) => item.startsWith('z_developer_test='))
    ?.slice('z_developer_test='.length);
  if (!token) return false;
  const expiresAt = developerTestSessions.get(token);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    developerTestSessions.delete(token);
    return false;
  }
  return true;
}

app.get(['/developer-api-test', '/developer-api-test.html'], async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Super-admin access is required.');
  if (!process.env.DEVELOPER_API_TEST_PASSWORD_HASH) {
    return res.status(503).send('The API test password is not configured.');
  }
  const file = getDeveloperTestSession(req) ? 'developer-api-test.html' : 'developer-api-test-lock.html';
  res.set('Cache-Control', 'no-store');
  return res.sendFile(path.join(__dirname, '..', 'client', file));
});

app.post('/api/developer-api-test/unlock', developerTestUnlockRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is required.' });
  const passwordHash = process.env.DEVELOPER_API_TEST_PASSWORD_HASH;
  if (!passwordHash) return res.status(503).json({ error: 'The API test password is not configured.' });
  if (!verifyDeveloperTestPassword(req.body?.password, passwordHash)) {
    return res.status(401).json({ error: 'The password is incorrect.' });
  }
  const now = Date.now();
  for (const [session, expiresAt] of developerTestSessions) {
    if (expiresAt <= now) developerTestSessions.delete(session);
  }
  const token = randomBytes(32).toString('hex');
  developerTestSessions.set(token, now + developerTestSessionDurationMs);
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `z_developer_test=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(developerTestSessionDurationMs / 1000)}${secure}`);
  return res.json({ unlocked: true });
});

app.get('/sell/billing', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.findOne({ ownerId: user._id });
  if (shop?.sellerSuspended) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  if (!shop) return res.redirect('/sell/setup');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell-billing.html'));
});

app.get('/sell/profile', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  const shop = await Shop.findOne({ ownerId: user._id });
  if (shop?.sellerSuspended) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  if (!shop) return res.redirect('/sell/setup');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell-profile.html'));
});

app.get('/sell/assistant', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  if (await isSellerSuspended(user)) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell-assistant.html'));
});

app.get('/sell/verification', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.redirect('/login');
  if (await isSellerSuspended(user)) return res.redirect('/dashboard?section=profile&sellerSuspended=1');
  return res.sendFile(path.join(__dirname, '..', 'client', 'sell-verification.html'));
});

app.get('/terms', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'terms.html'));
});

app.get('/support', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'support.html'));
});

app.get('/account-suspended', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'account-suspended.html'));
});

app.get('/admin/payouts', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-payouts.html'));
});

app.get('/admin/statement-verification', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-statement-verification.html'));
});

app.get('/admin/moderation', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).send('Moderator access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-moderation.html'));
});

app.get('/admin/login-wallpaper', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).send('Moderator access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-login-wallpaper.html'));
});

app.get('/admin/login-wallpaper/preview', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).send('Moderator access is not configured for this account.');
  const policy = [
    "default-src 'self'",
    "base-uri 'self'",
    "font-src 'self' https://fonts.gstatic.com",
    "form-action 'self'",
    "frame-ancestors 'self'",
    "img-src 'self' data: blob: https:",
    "object-src 'none'",
    "script-src 'self' 'unsafe-inline'",
    "script-src-attr 'none'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "frame-src 'self' https://www.google.com",
    "connect-src 'self'"
  ];
  if (process.env.NODE_ENV === 'production') policy.push('upgrade-insecure-requests');
  res.removeHeader('Content-Security-Policy');
  res.setHeader('Content-Security-Policy', policy.join('; '));
  return res.sendFile(path.join(__dirname, '..', 'client', 'home.html'));
});

app.get('/admin/support', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).send('Moderator access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-support.html'));
});

app.get('/admin/kyc', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-kyc.html'));
});

app.get('/admin/accounts', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-accounts.html'));
});

app.get('/admin/notifications', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-notifications.html'));
});

app.get('/admin/accounts/:id/activity', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).send('Account not found.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-user-activity.html'));
});

app.get('/admin/accounts/:id/details', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).send('Account not found.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-user-details.html'));
});

app.get('/admin/accounts/:id/transactions', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Admin access is not configured for this account.');
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).send('Account not found.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-user-transactions.html'));
});

app.get('/admin/platform', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Super-admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-platform.html'));
});

app.get('/admin/server-config', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Super-admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-server-config.html'));
});

app.get('/admin/commands', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).send('Super-admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', 'admin-commands.html'));
});

app.get('/cart', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'cart.html'));
});

app.get('/checkout', async (req, res) => {
  if (!await getSessionUser(req)) return res.redirect(`/login?returnTo=${encodeURIComponent('/cart')}`);
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

const protectedAdminFiles = {
  '/admin-payouts.html': { file: 'admin-payouts.html', allow: isAdminUser },
  '/admin-moderation.html': { file: 'admin-moderation.html', allow: isModeratorUser },
  '/admin-login-wallpaper.html': { file: 'admin-login-wallpaper.html', allow: isModeratorUser },
  '/admin-support.html': { file: 'admin-support.html', allow: isAdminUser },
  '/admin-kyc.html': { file: 'admin-kyc.html', allow: isAdminUser },
  '/admin-accounts.html': { file: 'admin-accounts.html', allow: isAdminUser },
  '/admin-notifications.html': { file: 'admin-notifications.html', allow: isAdminUser },
  '/admin-platform.html': { file: 'admin-platform.html', allow: isAdminUser },
  '/admin-statement-verification.html': { file: 'admin-statement-verification.html', allow: isAdminUser }
};

app.get(Object.keys(protectedAdminFiles), async (req, res) => {
  const page = protectedAdminFiles[req.path];
  const user = await getSessionUser(req);
  if (!user || !page.allow(user)) return res.status(403).send('Admin access is not configured for this account.');
  return res.sendFile(path.join(__dirname, '..', 'client', page.file));
});

app.use(express.static(path.join(__dirname, '..', 'client')));

function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function describeLoginDevice(userAgent = '') {
  const agent = typeof userAgent === 'string' ? userAgent.slice(0, 500) : '';
  const browser = /Edg\//i.test(agent) ? 'Edge'
    : /OPR\//i.test(agent) ? 'Opera'
      : /Firefox\//i.test(agent) ? 'Firefox'
        : /Chrome\//i.test(agent) && !/Chromium\//i.test(agent) ? 'Chrome'
          : /Safari\//i.test(agent) && !/Chrome\//i.test(agent) ? 'Safari'
            : 'Unknown browser';
  const platform = /Windows/i.test(agent) ? 'Windows'
    : /Android/i.test(agent) ? 'Android'
      : /iPhone|iPad|iPod/i.test(agent) ? 'iOS'
        : /Macintosh|Mac OS/i.test(agent) ? 'macOS'
          : /Linux/i.test(agent) ? 'Linux'
            : 'unknown device';
  return `${browser} on ${platform}`;
}

function getSafeReturnPath(value, fallback = '/dashboard') {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) {
    return fallback;
  }
  const destination = new URL(value, 'http://z.local');
  if (destination.origin !== 'http://z.local' || destination.pathname === '/login' || destination.pathname.startsWith('/login/')) {
    return fallback;
  }
  return `${destination.pathname}${destination.search}${destination.hash}`;
}

function normalizeProfileInput(input = {}, towns = namibianTowns) {
  const name = typeof input.name === 'string' ? input.name.trim() : '';
  const phone = typeof input.phone === 'string' ? input.phone.trim() : '';
  const town = typeof input.town === 'string' ? input.town.trim() : '';
  if (!name || name.length > 80) throw apiError(400, 'Enter a name between 1 and 80 characters.');
  const phoneDigits = phone.replace(/\D/g, '');
  if (phone && (!/^\+?[0-9][0-9\s()-]{6,19}$/.test(phone) || phoneDigits.length < 7 || phoneDigits.length > 15)) {
    throw apiError(400, 'Enter a valid phone number.');
  }
  if (town && !towns.includes(town)) throw apiError(400, 'Choose a valid town.');
  return { name, phone, town };
}

function isValidEmailVerificationToken(token) {
  return typeof token === 'string' && /^[a-f0-9]{64}$/.test(token);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isEmailVerified(user) {
  return Boolean(user?.emailVerified);
}

function createReferralCode() {
  return randomBytes(6).toString('hex').toUpperCase();
}

function isConfiguredAdminIdentity(user, configuredEmail = process.env.ADMIN_EMAIL, configuredId = process.env.ADMIN_USER_ID) {
  const adminEmail = normalizeEmail(configuredEmail);
  const configuredAdminId = configuredId || '';
  const userId = user?._id?.toString?.() || user?.id || '';
  const identityMatches = mongoose.isValidObjectId(configuredAdminId) && userId === configuredAdminId;
  return Boolean(adminEmail && user && normalizeEmail(user.email) === adminEmail && identityMatches);
}

function isAdminUser(user, configuredEmail = process.env.ADMIN_EMAIL, configuredId = process.env.ADMIN_USER_ID) {
  return Boolean(isConfiguredAdminIdentity(user, configuredEmail, configuredId) && isEmailVerified(user));
}

function isLocalMongoUri(mongodbUri = process.env.MONGODB_URI) {
  if (typeof mongodbUri !== 'string') return false;
  try {
    const hostname = new URL(mongodbUri).hostname.replace(/^\[|\]$/g, '').toLowerCase();
    return ['localhost', '127.0.0.1', '::1'].includes(hostname);
  } catch {
    return false;
  }
}

function isSandboxUser(user, {
  nodeEnv = process.env.NODE_ENV,
  sandboxEmail = process.env.SANDBOX_EMAIL,
  mongodbUri = process.env.MONGODB_URI
} = {}) {
  return Boolean(
    nodeEnv !== 'production'
    && isLocalMongoUri(mongodbUri)
    && normalizeEmail(sandboxEmail)
    && normalizeEmail(user?.email) === normalizeEmail(sandboxEmail)
    && user?.role === 'sandbox'
  );
}

function isModeratorUser(user) {
  return Boolean(user && (isAdminUser(user) || (user.role === 'moderator' && isEmailVerified(user))));
}

function getPublicRole(user) {
  if (isAdminUser(user)) return 'super_admin';
  if (isModeratorUser(user)) return 'moderator';
  if (isSandboxUser(user)) return 'sandbox';
  return 'customer';
}

function isValidCommissionRatePercent(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100;
}

async function getPlatformCommissionRate() {
  const setting = await PlatformSetting.findOne({ key: 'commission_rate' }).select('commissionRate').lean();
  const activeRate = setting?.commissionRate ?? commissionRate;
  if (!Number.isFinite(activeRate) || activeRate < 0 || activeRate > 1) {
    throw new Error('Stored platform commission rate must be between 0 and 1.');
  }
  return activeRate;
}

async function getUnavailableShopIds() {
  const now = new Date();
  return Shop.distinct('_id', {
    $and: [
      { $or: [
        { sellerSuspended: true },
        { sellerRestrictionStatus: 'banned' },
        { sellerRestrictionStatus: 'temp_hold', sellerRestrictedUntil: { $gt: now } },
        { approvalStatus: { $in: ['pending', 'rejected'] } }
      ] }
    ]
  });
}

async function isSellerSuspended(user) {
  const shop = await Shop.findOne({ ownerId: user._id }).select('sellerSuspended').lean();
  return Boolean(shop?.sellerSuspended);
}

function isSellerInventoryRestricted(shop, now = new Date()) {
  return Boolean(shop?.sellerSuspended || isSellerAutoRestricted(shop, now));
}

function isPublicSellerShop(shop, now = new Date()) {
  return Boolean(shop
    && !shop.sellerSuspended
    && !['pending', 'rejected'].includes(shop.approvalStatus)
    && !isSellerAutoRestricted(shop, now));
}

function sellerRestrictionError(shop) {
  if (shop?.sellerRestrictionStatus === 'banned') {
    return 'Seller access is permanently disabled. Buyer access remains available.';
  }
  if (isSellerAutoRestricted(shop)) {
    return `Seller inventory and payouts are temporarily restricted until ${new Date(shop.sellerRestrictedUntil).toLocaleString()}. Buyer access and order fulfillment remain available.`;
  }
  if (shop?.sellerSuspended) return 'Seller access is suspended. Buyer access remains available.';
  return null;
}

function getPublicShopFilter(now = new Date()) {
  return {
    $and: [
      { sellerSuspended: { $ne: true } },
      { approvalStatus: { $in: ['approved', null] } },
      { $or: [
        { sellerRestrictionStatus: { $nin: ['temp_hold', 'banned'] } },
        { sellerRestrictionStatus: 'temp_hold', sellerRestrictedUntil: { $lte: now } }
      ] }
    ]
  };
}

async function applyAutomaticSellerRestriction(shopId, now = new Date()) {
  const shopState = await Shop.findById(shopId).select('sellerRestrictionLastTriggeredAt').lean();
  if (!shopState) return false;
  const thresholdEvents = await ListingThresholdEvent.find({
    shopId,
    triggeredAt: { $gte: new Date(now.getTime() - sellerRestrictionWindowMs), $lte: now }
  }).select('productId triggeredAt').lean();
  if (!shouldAutoRestrictSeller(thresholdEvents, now, shopState.sellerRestrictionLastTriggeredAt)) return false;

  const restrictedUntil = new Date(now.getTime() + sellerRestrictionDurationMs);
  const shop = await Shop.findOneAndUpdate({
    _id: shopId,
    sellerSuspended: { $ne: true },
    sellerRestrictionStatus: { $in: ['active', null] }
  }, {
    $set: {
      sellerRestrictionStatus: 'temp_hold',
      sellerRestrictedUntil: restrictedUntil,
      sellerRestrictionLastTriggeredAt: now,
      sellerRestrictionReason: 'Three separate listings reached the report threshold within 48 hours.'
    }
  }, { returnDocument: 'after' }).select('_id ownerId name sellerRestrictedUntil').lean();
  if (!shop) return false;

  const owner = await User.findById(shop.ownerId).select('name email').lean();
  await recordModerationAudit({
    action: 'seller_access_auto_held',
    actorType: 'system',
    targetType: 'account',
    targetId: shop.ownerId.toString(),
    targetLabel: `${owner?.name || 'Seller'} (${owner?.email || 'email unavailable'})`,
    details: `Automated 24-hour seller-access hold for shop ${shop.name} (${shop._id.toString()}); three separate listings reached 50 report points within 48 hours. Hold expires ${shop.sellerRestrictedUntil.toISOString()}. Buyer access and order fulfillment remain available.`
  });
  return true;
}

async function expireAutomaticSellerRestrictions(now = new Date()) {
  const expiredShops = await Shop.find({
    sellerRestrictionStatus: 'temp_hold',
    sellerRestrictedUntil: { $lte: now }
  }).limit(100).select('_id ownerId name sellerRestrictedUntil').lean();
  for (const shop of expiredShops) {
    const released = await Shop.findOneAndUpdate({
      _id: shop._id,
      sellerRestrictionStatus: 'temp_hold',
      sellerRestrictedUntil: { $lte: now }
    }, {
      $set: { sellerRestrictionStatus: 'active', sellerRestrictedUntil: null, sellerRestrictionReason: '' }
    }, { returnDocument: 'after' }).select('_id').lean();
    if (!released) continue;
    const owner = await User.findById(shop.ownerId).select('name email').lean();
    await recordModerationAudit({
      action: 'seller_access_auto_released',
      actorType: 'system',
      targetType: 'account',
      targetId: shop.ownerId.toString(),
      targetLabel: `${owner?.name || 'Seller'} (${owner?.email || 'email unavailable'})`,
      details: `Automated 24-hour seller-access hold expired for shop ${shop.name} (${shop._id.toString()}).`
    });
  }
}

async function processAutomaticSellerRestrictions(now = new Date()) {
  await expireAutomaticSellerRestrictions(now);
  const recentThresholdListings = await Product.find({
    moderationStatus: 'hidden',
    moderationSource: 'report_threshold',
    moderatedAt: { $gte: new Date(now.getTime() - sellerRestrictionWindowMs), $lte: now }
  }).select('_id shopId moderatedAt').lean();
  for (const product of recentThresholdListings) {
    await ListingThresholdEvent.updateOne({
      shopId: product.shopId,
      productId: product._id,
      triggeredAt: product.moderatedAt
    }, {
      $setOnInsert: {
        shopId: product.shopId,
        productId: product._id,
        triggeredAt: product.moderatedAt
      }
    }, { upsert: true });
  }
  const candidates = await ListingThresholdEvent.aggregate([
    { $match: { triggeredAt: { $gte: new Date(now.getTime() - sellerRestrictionWindowMs), $lte: now } } },
    { $group: { _id: '$shopId', products: { $addToSet: '$productId' } } },
    { $match: { $expr: { $gte: [{ $size: '$products' }, sellerRestrictionThreshold] } } },
    { $limit: 100 }
  ]);
  for (const candidate of candidates) await applyAutomaticSellerRestriction(candidate._id, now);
}

function assertProductionAdminConfiguration(nodeEnv = process.env.NODE_ENV, adminEmail = process.env.ADMIN_EMAIL, adminUserId = process.env.ADMIN_USER_ID) {
  if (nodeEnv === 'production' && (normalizeEmail(adminEmail) !== 'z@gmail.com' || !mongoose.isValidObjectId(adminUserId))) {
    throw new Error('Production startup blocked: configure ADMIN_EMAIL=z@gmail.com and the verified account ADMIN_USER_ID.');
  }
}

function publicUser(user) {
  return {
    id: user.id || user._id.toString(),
    name: user.name,
    email: user.email,
    emailVerified: Boolean(user.emailVerified),
    phone: user.phone || '',
    town: user.town || '',
    role: getPublicRole(user),
    isModerator: isModeratorUser(user),
    isSuperAdmin: isAdminUser(user)
  };
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

function resolveAppBaseUrl({
  appBaseUrl = process.env.APP_BASE_URL,
  renderExternalUrl = process.env.RENDER_EXTERNAL_URL,
  nodeEnv = process.env.NODE_ENV,
  port = process.env.PORT || 3001
} = {}) {
  let baseUrl = appBaseUrl;
  if (renderExternalUrl) {
    try {
      const configuredHost = baseUrl ? new URL(baseUrl).hostname : '';
      if (!baseUrl || ['localhost', '127.0.0.1', '::1'].includes(configuredHost)) {
        baseUrl = renderExternalUrl;
      }
    } catch {
      baseUrl = renderExternalUrl;
    }
  }
  if (!baseUrl && nodeEnv !== 'production') baseUrl = `http://localhost:${port}`;
  if (!baseUrl) return null;

  try {
    const url = new URL(baseUrl);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    if (nodeEnv === 'production' && url.protocol !== 'https:') return null;
    return url.origin;
  } catch {
    return null;
  }
}

async function createEmailVerification(user) {
  if (process.env.NODE_ENV === 'production' && (!passwordResetMailer || !resolveAppBaseUrl())) {
    throw apiError(503, 'Email verification is not configured. Contact Z support.');
  }
  const baseUrl = resolveAppBaseUrl();
  if (!baseUrl) throw apiError(503, 'The public application URL is not configured.');
  const token = randomBytes(32).toString('hex');
  await EmailVerification.findOneAndUpdate(
    { userId: user._id },
    { $set: { tokenHash: hashSessionToken(token), expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) } },
    { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
  );
  const verificationUrl = new URL(`/verify-email?token=${encodeURIComponent(token)}`, baseUrl).toString();
  if (process.env.NODE_ENV === 'production') {
    await passwordResetMailer.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: user.email,
      subject: 'Verify your Z email address',
      text: `Hello ${user.name},\n\nVerify your Z email address within 24 hours:\n${verificationUrl}\n\nIf you did not create this account, you can ignore this email.`
    });
    return '';
  }
  return verificationUrl;
}

async function createSession(res, user, onCreated = null) {
  const token = randomBytes(32).toString('hex');
  const session = await Session.create({
    tokenHash: hashSessionToken(token),
    userId: user._id,
    expiresAt: new Date(Date.now() + sessionDuration)
  });
  try {
    if (onCreated) await onCreated();
  } catch (error) {
    await Session.deleteOne({ _id: session._id });
    throw error;
  }
  setSessionCookie(res, token, Math.floor(sessionDuration / 1000));
}

async function getSessionUser(req) {
  const token = getSessionToken(req);
  if (!token) return null;

  const session = await Session.findOne({
    tokenHash: hashSessionToken(token),
    expiresAt: { $gt: new Date() }
  }).populate('userId');

  const user = session?.userId || null;
  return user?.isSuspended ? null : user;
}

async function authenticateDeveloperApplication(req, res) {
  const appId = req.get('x-z-app-id') || '';
  const authorization = req.get('authorization') || '';
  const token = authorization.match(/^Bearer (zstmt_live_[A-Za-z0-9_-]{43})$/)?.[1] || '';
  if (!/^[\da-f-]{36}$/i.test(appId) || !isValidDeveloperToken(token)) {
    res.set('WWW-Authenticate', 'Bearer');
    res.status(401).json({ error: 'Provide a valid X-Z-App-Id and Bearer API token.' });
    return null;
  }
  const application = await DeveloperApplication.findOne({
    appId,
    tokenHash: hashDeveloperToken(token),
    revokedAt: null
  }).populate('ownerId', 'emailVerified isSuspended');
  if (!application || !application.ownerId || application.ownerId.isSuspended || !isEmailVerified(application.ownerId)) {
    res.set('WWW-Authenticate', 'Bearer');
    res.status(401).json({ error: 'The application ID or API token is invalid or revoked.' });
    return null;
  }
  req.developerApiAppId = application.appId;
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    res.status(400).json({ error: 'Use HTTPS for developer API requests.' });
    return null;
  }
  application.lastUsedAt = new Date();
  await application.save();
  return application;
}

function trackDeveloperApiUsage(endpoint) {
  return (req, res, next) => {
    const startedAt = Date.now();
    res.once('finish', () => {
      const day = new Date();
      day.setUTCHours(0, 0, 0, 0);
      const counters = getDeveloperApiUsageCounters(res.statusCode, req.developerApiOutcome || null);
      const key = { day, endpoint, appId: req.developerApiAppId || null };
      const update = {
        $inc: { ...counters, totalDurationMs: Math.max(0, Date.now() - startedAt) },
        $setOnInsert: { expiresAt: new Date(day.getTime() + 400 * 24 * 60 * 60 * 1000) }
      };
      DeveloperApiUsage.updateOne(key, update, { upsert: true }).catch(async (error) => {
        if (error?.code === 11000) {
          try {
            await DeveloperApiUsage.updateOne(key, { $inc: update.$inc });
            return;
          } catch (retryError) {
            console.error(`Could not record developer API usage: ${retryError.message}`);
            return;
          }
        }
        console.error(`Could not record developer API usage: ${error.message}`);
      });
    });
    next();
  };
}

function apiError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function normalizeSupportRequest(input = {}) {
  const topic = input.topic;
  const message = typeof input.message === 'string' ? input.message.trim() : '';
  if (!SUPPORT_TOPICS.includes(topic) || message.length < 10 || message.length > 1500) {
    throw apiError(400, 'Choose a support topic and enter a message between 10 and 1500 characters.');
  }
  return { topic, message };
}

const SUPPORT_TOPICS = [
  'delivery', 'refund', 'return', 'item_issue', 'other',
  'listing_storefront', 'platform_navigation', 'delayed_payout', 'banking_details',
  'fee_commission', 'transaction_failure', 'rejected_business_application',
  'document_upload_failure', 'account_reinstatement'
];
const GENERAL_SUPPORT_TOPICS = ['delivery', 'refund', 'return', 'item_issue', 'other', 'listing_storefront', 'platform_navigation'];
const SUPPORT_TRIAGE_TEMPLATES = {
  delivery: {
    issue: 'Order delivery update needed',
    draft: 'Thanks for contacting Z about your order. We will review the delivery details and share an update here. If you have a tracking reference or a recent delivery update, please add it to your reply.'
  },
  refund: {
    issue: 'Refund status or eligibility question',
    draft: 'Thanks for contacting Z about a refund. We will review the order and the request details before confirming the available next steps. Please reply with the order number if it is not already included.'
  },
  return: {
    issue: 'Return process or eligibility question',
    draft: 'Thanks for contacting Z about a return. We will review the order details and follow up with the applicable next steps. Please let us know which item you are asking about if the order contains multiple items.'
  },
  item_issue: {
    issue: 'Problem with an item received',
    draft: 'Thanks for letting us know about the item issue. We will review the order details and your description to determine the next steps. If useful, reply with the item name and a description of the mismatch or damage.'
  },
  other: {
    issue: 'General marketplace question',
    draft: 'Thanks for contacting Z. We have received your question and will review it. If there are specific steps or a page where the issue occurred, please include those details in your reply.'
  },
  listing_storefront: {
    issue: 'Listing or storefront assistance needed',
    draft: 'Thanks for contacting Z about your listing or storefront. We will review the details and help identify the next steps. Please mention the page or listing involved and what you were trying to change.'
  },
  platform_navigation: {
    issue: 'Account settings or platform navigation help',
    draft: 'Thanks for contacting Z. We will review the account or navigation issue you described. For your security, do not send your password or sign-in codes; please describe the page and action that caused the problem.'
  },
  delayed_payout: {
    issue: 'Vendor payout status inquiry',
    draft: 'Thanks for contacting Z about a payout. The Super Admin will review the payout status and follow up here. Please do not include bank account numbers or other full banking credentials in your message.'
  },
  banking_details: {
    issue: 'Payout banking detail update request',
    draft: 'Thanks for contacting Z about payout details. The Super Admin will review your request and provide the appropriate next steps through this private support case. Please do not post full bank account numbers here.'
  },
  fee_commission: {
    issue: 'Platform fee or commission inquiry',
    draft: 'Thanks for contacting Z about a fee or commission. The Super Admin will review the relevant order and fee details before replying. Please include the order number if it is not already attached; do not include payment-card details.'
  },
  transaction_failure: {
    issue: 'Checkout or payment failure report',
    draft: 'Thanks for reporting the payment issue. The Super Admin will review the checkout details and follow up here. Please do not retry if you are unsure whether a payment completed, and do not send full card or banking details.'
  },
  rejected_business_application: {
    issue: 'Business application review question',
    draft: 'Thanks for contacting Z about your business application. The Super Admin will review the application status and the information available on your account, then reply here with the next steps. Please do not attach identity documents to this message.'
  },
  document_upload_failure: {
    issue: 'Business document upload problem',
    draft: 'Thanks for reporting the document upload problem. The Super Admin will review the issue and follow up with guidance. Please do not attach legal or identity documents in this support message.'
  },
  account_reinstatement: {
    issue: 'Suspended account reinstatement appeal',
    draft: 'Thanks for submitting an appeal. The Super Admin will review the account status and the information in your case, then respond here with an update. This message does not guarantee reinstatement.'
  }
};

const SUPPORT_ISSUE_RULES = {
  delivery: [
    { issue: 'Delivery is late or delayed', terms: ['late', 'delay', 'delayed', 'not arrived', 'still waiting'], draft: 'Thanks for letting us know your delivery is delayed. We will check the available order and delivery information and update you here. If the delivery estimate has passed, please confirm your order number and delivery town.' },
    { issue: 'Tracking is missing or not updating', terms: ['tracking', 'track', 'no update', 'not updating', 'tracking number'], draft: 'Thanks for reporting the tracking issue. We will review the order status and available tracking information. If you have a tracking reference, you can share that reference here; do not include private account credentials.' },
    { issue: 'Order marked delivered but not received', terms: ['marked delivered', 'shows delivered', 'did not receive', 'not received', 'missing parcel'], draft: 'Thanks for letting us know the order is marked delivered but has not reached you. We will review the delivery details. Please confirm that the delivery town and contact details on the order are correct.' }
  ],
  refund: [
    { issue: 'Refund timing question', terms: ['refund pending', 'refund status', 'when refund', 'refund not received', 'waiting for refund'], draft: 'Thanks for checking on your refund. We will review the order and any recorded refund status before confirming the next steps. We cannot confirm a completion date until those details have been checked.' }
  ],
  return: [
    { issue: 'Return request for an item', terms: ['return item', 'send it back', 'return this', 'return label'], draft: 'Thanks for your return request. We will review the order and item details, then reply with the next steps that apply. Please identify the item if your order contained more than one.' }
  ],
  item_issue: [
    { issue: 'Wrong item received', terms: ['wrong item', 'different item', 'not what i ordered', 'incorrect item'], draft: 'Thanks for reporting that you received a different item. We will review the order details. Please tell us the item you expected and the item you received so we can understand the mismatch.' },
    { issue: 'Item arrived damaged', terms: ['damaged', 'broken', 'defective', 'does not work', 'cracked'], draft: 'Thanks for letting us know the item arrived damaged or is not working. We will review the order and your description. Please describe the affected item and the damage; do not include unrelated personal information.' },
    { issue: 'Size or colour does not match', terms: ['wrong size', 'wrong colour', 'wrong color', 'size mismatch', 'color mismatch', 'colour mismatch'], draft: 'Thanks for reporting the size or colour mismatch. We will compare the order details with the item you received. Please tell us the size or colour ordered and what arrived.' }
  ],
  listing_storefront: [
    { issue: 'Product image upload problem', terms: ['upload photo', 'upload image', 'picture upload', 'image will not', 'photo will not'], draft: 'Thanks for reporting the image upload problem. We will review the steps and listing involved. Please tell us what happens when you upload and which browser or device you are using; do not share passwords.' },
    { issue: 'Listing description or formatting help', terms: ['description', 'formatting', 'format text', 'edit listing'], draft: 'Thanks for asking about your listing. We will review the page and editing issue you described. Please mention the listing and the change you were trying to make.' },
    { issue: 'Shop or listing category help', terms: ['category', 'categories', 'shop profile', 'storefront'], draft: 'Thanks for contacting us about your shop or listing category. We will review the storefront details and help identify the next steps. Please include the shop or listing name.' }
  ],
  platform_navigation: [
    { issue: 'Password reset or sign-in link issue', terms: ['reset link', 'password reset', 'forgot password', 'sign in link', 'login link'], draft: 'Thanks for reporting the sign-in or reset-link problem. We will review the issue. For your security, never send your password or a one-time sign-in code in this case.' },
    { issue: 'Profile or account setting help', terms: ['profile', 'notification setting', 'preferences', 'account setting'], draft: 'Thanks for your question about account settings. We will review the page and setting involved. Please describe what you want to update and what happens when you try.' }
  ],
  delayed_payout: [
    { issue: 'Payout appears delayed', terms: ['late payout', 'payout delay', 'not received payout', 'payout has not', 'waiting for payout'], draft: 'Thanks for reporting the payout delay. The Super Admin will review the relevant payout status and follow up here. Please do not send full bank account details or passwords.' }
  ],
  banking_details: [
    { issue: 'Request to update payout bank details', terms: ['change bank', 'update bank', 'bank account change', 'new bank details', 'branch code'], draft: 'Thanks for requesting a payout-detail update. The Super Admin will review the request and provide a secure next step. Do not send full account numbers or banking credentials in this support message.' }
  ],
  fee_commission: [
    { issue: 'Question about a specific commission charge', terms: ['commission charge', 'commission amount', 'fee charged', 'wrong fee', 'fee is wrong'], draft: 'Thanks for querying the fee. The Super Admin will compare the relevant order with the applicable fee details and reply here. Please provide the order number if it is not already attached.' }
  ],
  transaction_failure: [
    { issue: 'Checkout timed out or payment failed', terms: ['timed out', 'timeout', 'payment failed', 'checkout failed', 'transaction failed'], draft: 'Thanks for reporting the checkout failure. The Super Admin will review the transaction status before advising you. Please do not share card numbers, security codes, or banking passwords.' }
  ],
  rejected_business_application: [
    { issue: 'Question about a rejected application', terms: ['why rejected', 'application rejected', 'rejected my', 'appeal rejection'], draft: 'Thanks for asking about the application decision. The Super Admin will review the application status and respond here with the next steps. Please do not attach identity documents to this message.' }
  ],
  document_upload_failure: [
    { issue: 'Document upload or validation failed', terms: ['upload failed', 'document will not upload', 'file too large', 'validation error', 'upload error'], draft: 'Thanks for reporting the document upload error. The Super Admin will review the issue and follow up with guidance. Please do not attach legal or identity documents in this support message.' }
  ],
  account_reinstatement: [
    { issue: 'Possible incorrect or unclear suspension', terms: ['mistake', 'wrongfully', 'incorrectly suspended', 'false positive', 'not told why', 'know why'], draft: 'Thanks for explaining your concern. The Super Admin will review the suspension reason and available account history before providing an update. This review does not guarantee reinstatement.' },
    { issue: 'Listing or marketplace policy concern', terms: ['listing', 'product', 'prohibited', 'counterfeit', 'policy violation', 'policy'], draft: 'Thanks for providing these details. The Super Admin will review the relevant listing and marketplace policy information before updating you. This review does not guarantee reinstatement.' },
    { issue: 'Account security or unauthorized access concern', terms: ['hacked', 'unauthorized', 'security', 'compromised', 'someone accessed'], draft: 'Thanks for reporting a possible account security issue. The Super Admin will review the account activity and security details before providing an update. Please do not send your password or sign-in codes.' },
    { issue: 'Identity or business verification concern', terms: ['verification', 'identity', 'kyc', 'document', 'business registration'], draft: 'Thanks for explaining the verification concern. The Super Admin will review the available verification status and account history before providing next steps. Do not send identity documents in this appeal.' },
    { issue: 'Payment or order-related concern', terms: ['payment', 'chargeback', 'refund', 'transaction', 'order'], draft: 'Thanks for providing the order or payment context. The Super Admin will review the relevant transaction records before providing an update. Please do not send full card or banking details.' }
  ]
};

function getSupportRequestVisibilityFilter(isSuperAdmin) {
  if (isSuperAdmin) return {};
  return {
    $or: [
      { category: 'general' },
      { category: { $exists: false }, topic: { $in: GENERAL_SUPPORT_TOPICS } }
    ]
  };
}

function getSupportCategory(topic) {
  if (['delayed_payout', 'banking_details', 'fee_commission', 'transaction_failure'].includes(topic)) return 'financial';
  if (['rejected_business_application', 'document_upload_failure', 'account_reinstatement'].includes(topic)) return 'identity';
  return 'general';
}

function getSupportTriage(topic, message) {
  const fallback = SUPPORT_TRIAGE_TEMPLATES[topic];
  if (!fallback) return null;
  const normalizedMessage = typeof message === 'string' ? message.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim() : '';
  const candidates = (SUPPORT_ISSUE_RULES[topic] || []).map((rule) => ({
    ...rule,
    matches: rule.terms.filter((term) => ` ${normalizedMessage} `.includes(` ${term} `)).length
  })).filter((rule) => rule.matches > 0).sort((left, right) => right.matches - left.matches);
  if (!candidates.length) {
    return {
      likelyIssue: topic === 'account_reinstatement' ? 'Appeal reason needs manual review' : fallback.issue,
      confidence: 45,
      confidenceLabel: 'Low',
      suggestedResponse: fallback.draft
    };
  }
  if (candidates.length > 1 && candidates[0].matches === candidates[1].matches) {
    return {
      likelyIssue: `Needs review: more than one ${topic.replaceAll('_', ' ')} issue may apply`,
      confidence: 50,
      confidenceLabel: 'Low',
      suggestedResponse: fallback.draft
    };
  }
  const matchCount = candidates[0].matches;
  const confidence = matchCount === 1 ? 65 : matchCount === 2 ? 80 : 90;
  return {
    likelyIssue: candidates[0].issue,
    confidence,
    confidenceLabel: confidence >= 80 ? 'High' : 'Medium',
    suggestedResponse: candidates[0].draft
  };
}

function normalizeSuspensionAppeal(input = {}) {
  const accountEmail = normalizeEmail(input.accountEmail);
  const reason = typeof input.reason === 'string' ? input.reason.trim() : '';
  const referenceId = typeof input.referenceId === 'string' ? input.referenceId.trim() : '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(accountEmail) || accountEmail.length > 254) {
    throw apiError(400, 'Enter a valid email address for the suspended account.');
  }
  if (reason.length < 20 || reason.length > 2000) {
    throw apiError(400, 'Explain your appeal in 20 to 2000 characters.');
  }
  if (referenceId.length > 100) {
    throw apiError(400, 'The reference ID must be 100 characters or fewer.');
  }
  return { accountEmail, reason, referenceId };
}

function normalizeSuspensionAppealStatusEmail(input = {}) {
  const accountEmail = normalizeEmail(input.accountEmail);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(accountEmail) || accountEmail.length > 254) {
    throw apiError(400, 'Enter a valid email address.');
  }
  return accountEmail;
}

function normalizeSuspensionAppealStatusAccess(input = {}) {
  const accountEmail = normalizeSuspensionAppealStatusEmail(input);
  const verificationToken = typeof input.verificationToken === 'string' ? input.verificationToken : '';
  if (!/^[a-f0-9]{64}$/.test(verificationToken)) {
    throw apiError(403, 'Sign in with the suspended account to check or submit an appeal.');
  }
  return { accountEmail, verificationToken };
}

function normalizeSuspensionAppealReview(input = {}) {
  const status = input.status;
  const reactivateAccount = input.reactivateAccount === true;
  if (!['open', 'in_review', 'resolved'].includes(status)) {
    throw apiError(400, 'Choose a valid appeal status.');
  }
  if (input.reactivateAccount !== undefined && typeof input.reactivateAccount !== 'boolean') {
    throw apiError(400, 'Choose whether to reactivate the account.');
  }
  if (reactivateAccount && status !== 'resolved') {
    throw apiError(400, 'Resolve the appeal to reactivate the account.');
  }
  return { status, reactivateAccount };
}

const listingReportAutoHideThreshold = 50;
const listingReportDismissalLimit = 3;
const sellerRestrictionThreshold = 3;
const sellerRestrictionWindowMs = 48 * 60 * 60 * 1000;
const sellerRestrictionDurationMs = 24 * 60 * 60 * 1000;

function shouldAutoRestrictSeller(thresholdEvents, now = new Date(), lastTriggeredAt = null) {
  if (!Array.isArray(thresholdEvents)) return false;
  const cutoff = new Date(now).getTime() - sellerRestrictionWindowMs;
  const previousTrigger = lastTriggeredAt ? new Date(lastTriggeredAt).getTime() : -Infinity;
  const affectedProducts = new Set(thresholdEvents
    .filter((event) => {
      const triggeredAt = new Date(event.triggeredAt).getTime();
      return Number.isFinite(triggeredAt)
        && triggeredAt >= cutoff
        && triggeredAt <= new Date(now).getTime()
        && triggeredAt > previousTrigger;
    })
    .map((event) => event.productId?.toString())
    .filter(Boolean));
  return affectedProducts.size >= sellerRestrictionThreshold;
}

function isSellerAutoRestricted(shop, now = new Date()) {
  if (shop?.sellerRestrictionStatus === 'banned') return true;
  if (shop?.sellerRestrictionStatus !== 'temp_hold') return false;
  return !shop.sellerRestrictedUntil || new Date(shop.sellerRestrictedUntil) > new Date(now);
}

function getListingReportCredibilityPoints({ verifiedBuyer = false, sellerReporter = false } = {}) {
  if (sellerReporter) return 0;
  return verifiedBuyer ? 25 : 5;
}

function isListingReportBlocked(dismissedReportCount = 0) {
  return Number.isFinite(dismissedReportCount) && dismissedReportCount >= listingReportDismissalLimit;
}

function shouldAutoHideListing(reportScore = 0) {
  return Number.isFinite(reportScore) && reportScore >= listingReportAutoHideThreshold;
}

function shouldRestoreReportHiddenListing(moderationSource, pendingReportScore = 0) {
  return moderationSource === 'report_threshold' && !shouldAutoHideListing(pendingReportScore);
}

async function recordModerationAudit({ actorId = null, actorType = 'moderator', action, targetType, targetId, targetLabel = '', details = '' }) {
  return ModerationAudit.create({ actorId, actorType, action, targetType, targetId, targetLabel, details });
}

async function notifyModeratorsOfSupportRequest(request) {
  if (request.category !== 'general' || getSupportCategory(request.topic) !== 'general') return 0;
  const moderators = await User.find({
    role: 'moderator',
    emailVerified: true,
    isSuspended: { $ne: true }
  }).select('_id').lean();
  if (!moderators.length) return 0;
  await SupportNotification.insertMany(moderators.map((moderator) => ({
    userId: moderator._id,
    supportRequestId: request._id
  })));
  return moderators.length;
}

async function notifyProductReviewDecision({ product, shop, seller, reviewDecision }) {
  let recipients;
  let title;
  let message;
  let destination;
  if (reviewDecision.reviewStatus === 'approved') {
    recipients = [{ _id: seller._id }];
    title = 'Product published';
    message = `"${product.title}" passed the automatic review checks and is now published in your shop.`;
    destination = 'seller';
  } else {
    recipients = [{ _id: seller._id }];
    title = 'Product listing rejected';
    message = `"${product.title || 'Untitled product'}" was rejected: ${reviewDecision.reviewReasons.join(' ')}`;
    destination = 'seller';
  }

  if (!recipients.length) {
    const error = 'No eligible account is available to receive the product review notice.';
    console.error(error);
    return error;
  }

  try {
    await AccountNotification.insertMany(recipients.map((recipient) => ({
      userId: recipient._id,
      createdBy: seller._id,
      title,
      message: message.slice(0, 1000),
      destination
    })));
    return null;
  } catch (error) {
    console.error('Product review notification could not be delivered:', error);
    return 'The product was saved, but its review notification could not be delivered.';
  }
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
  mockPaymentsRequested = process.env.MOCK_PAYMENTS_ENABLED !== 'false',
  allowMockPaymentsInProduction = process.env.ALLOW_MOCK_PAYMENTS_IN_PRODUCTION === 'true'
) {
  if (nodeEnv === 'production' && paymentMode === 'mock' && mockPaymentsRequested && !allowMockPaymentsInProduction) {
    throw new Error('Production startup blocked: set ALLOW_MOCK_PAYMENTS_IN_PRODUCTION=true only for a test deployment, or set MOCK_PAYMENTS_ENABLED=false to disable checkout.');
  }
}

function resolvePayoutStatus(sellerOrder, now) {
  const currentStatus = sellerOrder?.payoutStatus || 'held';
  const eligibleAt = sellerOrder?.payoutEligibleAt ? new Date(sellerOrder.payoutEligibleAt) : null;
  if (sellerOrder?.fulfillmentStatus !== 'delivered' || !eligibleAt || eligibleAt > now) return currentStatus;
  if (currentStatus === 'held') return 'eligible';
  return currentStatus;
}

function roundNAD(value) {
  return Math.round((value + Number.EPSILON) * 100) / 100;
}

function reconcileWalletBalance(accountBalanceNAD, ledgerSummary) {
  const accountBalanceCents = Math.round(Number(accountBalanceNAD) * 100);
  if (!Number.isSafeInteger(accountBalanceCents) || accountBalanceCents < 0) {
    throw new TypeError('Account wallet balance must be a non-negative monetary amount.');
  }
  if (!ledgerSummary || !ledgerSummary.transactionCount) {
    return {
      status: 'unverified',
      transactionCount: 0,
      accountBalanceNAD: roundNAD(accountBalanceCents / 100),
      ledgerBalanceNAD: null,
      expectedBalanceNAD: null,
      openingBalanceNAD: null,
      creditsNAD: 0,
      debitsNAD: 0,
      refundsNAD: 0,
      matchedBalanceNAD: null,
      differenceNAD: null,
      ledgerIntegrityDifferenceNAD: null,
      unverifiedBalanceNAD: roundNAD(accountBalanceCents / 100)
    };
  }

  const toCents = (value, label) => {
    const cents = Math.round(Number(value) * 100);
    if (!Number.isSafeInteger(cents) || cents < 0) throw new TypeError(`${label} must be a non-negative monetary amount.`);
    return cents;
  };
  if (!['seller_credit', 'purchase_debit', 'purchase_refund'].includes(ledgerSummary.firstType)) {
    throw new TypeError('First wallet transaction has an unsupported type.');
  }
  const amountCents = toCents(ledgerSummary.firstAmountNAD, 'First wallet transaction amount');
  const firstBalanceCents = toCents(ledgerSummary.firstBalanceAfterNAD, 'First recorded wallet balance');
  const ledgerBalanceCents = toCents(ledgerSummary.lastBalanceAfterNAD, 'Latest recorded wallet balance');
  const creditsCents = toCents(ledgerSummary.creditsNAD || 0, 'Wallet credits');
  const debitsCents = toCents(ledgerSummary.debitsNAD || 0, 'Wallet debits');
  const refundsCents = toCents(ledgerSummary.refundsNAD || 0, 'Wallet refunds');
  const firstMovementCents = ledgerSummary.firstType === 'purchase_debit' ? -amountCents : amountCents;
  const openingBalanceCents = firstBalanceCents - firstMovementCents;
  const expectedBalanceCents = openingBalanceCents + creditsCents + refundsCents - debitsCents;
  const differenceCents = accountBalanceCents - ledgerBalanceCents;
  const ledgerIntegrityDifferenceCents = expectedBalanceCents - ledgerBalanceCents;
  const status = differenceCents === 0 && ledgerIntegrityDifferenceCents === 0 ? 'matched' : 'mismatch';

  return {
    status,
    transactionCount: ledgerSummary.transactionCount,
    accountBalanceNAD: roundNAD(accountBalanceCents / 100),
    ledgerBalanceNAD: roundNAD(ledgerBalanceCents / 100),
    expectedBalanceNAD: roundNAD(expectedBalanceCents / 100),
    openingBalanceNAD: roundNAD(openingBalanceCents / 100),
    creditsNAD: roundNAD(creditsCents / 100),
    debitsNAD: roundNAD(debitsCents / 100),
    refundsNAD: roundNAD(refundsCents / 100),
    matchedBalanceNAD: roundNAD(Math.max(0, Math.min(accountBalanceCents, ledgerBalanceCents)) / 100),
    differenceNAD: roundNAD(differenceCents / 100),
    ledgerIntegrityDifferenceNAD: roundNAD(ledgerIntegrityDifferenceCents / 100),
    unverifiedBalanceNAD: 0
  };
}

async function updateWalletReconciliationAlert(admin, account, reconciliation) {
  const now = new Date();
  if (reconciliation.status !== 'mismatch') {
    await WalletReconciliationAlert.updateOne(
      { accountId: account._id, status: 'open' },
      { $set: { status: 'resolved', resolvedAt: now, lastCheckedAt: now } }
    );
    return { adminNotified: false };
  }

  const pipeline = [{
    $set: {
      accountId: account._id,
      status: 'open',
      accountBalanceNAD: reconciliation.accountBalanceNAD,
      ledgerBalanceNAD: reconciliation.ledgerBalanceNAD,
      expectedBalanceNAD: reconciliation.expectedBalanceNAD,
      matchedBalanceNAD: reconciliation.matchedBalanceNAD,
      differenceNAD: reconciliation.differenceNAD,
      ledgerIntegrityDifferenceNAD: reconciliation.ledgerIntegrityDifferenceNAD,
      transactionCount: reconciliation.transactionCount,
      openedAt: {
        $cond: [
          { $eq: ['$status', 'open'] },
          { $ifNull: ['$openedAt', now] },
          now
        ]
      },
      generation: {
        $cond: [
          { $eq: ['$status', 'open'] },
          { $ifNull: ['$generation', 1] },
          { $add: [{ $ifNull: ['$generation', 0] }, 1] }
        ]
      },
      resolvedAt: null,
      lastCheckedAt: now
    }
  }];
  let alert;
  try {
    alert = await WalletReconciliationAlert.findOneAndUpdate(
      { accountId: account._id },
      pipeline,
      { upsert: true, new: true }
    );
  } catch (error) {
    if (error?.code !== 11000) throw error;
    alert = await WalletReconciliationAlert.findOneAndUpdate(
      { accountId: account._id },
      pipeline,
      { new: true }
    );
    if (!alert) throw new Error('Could not update the wallet reconciliation alert after a concurrent update.');
  }

  const claim = await WalletReconciliationAlert.findOneAndUpdate({
    _id: alert._id,
    generation: alert.generation,
    notifiedGeneration: { $ne: alert.generation }
  }, {
    $set: { notifiedGeneration: alert.generation }
  }, { new: true });
  if (claim) {
    const differenceDescription = reconciliation.differenceNAD === 0
      ? `Ledger activity implies N$ ${reconciliation.expectedBalanceNAD.toFixed(2)}, but the final recorded balance is N$ ${reconciliation.ledgerBalanceNAD.toFixed(2)}.`
      : `The account balance is N$ ${reconciliation.differenceNAD > 0 ? 'higher' : 'lower'} than the ledger by N$ ${Math.abs(reconciliation.differenceNAD).toFixed(2)}.`;
    const message = `${account.name || 'Unnamed account'} (${account.email}) has a wallet reconciliation discrepancy. ${differenceDescription} Matching balance amount: N$ ${reconciliation.matchedBalanceNAD.toFixed(2)}. Review the account activity before taking action.`;
    try {
      await AccountNotification.create({
        userId: admin._id,
        createdBy: admin._id,
        title: 'Wallet reconciliation discrepancy',
        message,
        destination: 'account'
      });
    } catch (error) {
      await WalletReconciliationAlert.updateOne(
        { _id: alert._id, notifiedGeneration: alert.generation },
        { $set: { notifiedGeneration: null } }
      );
      throw error;
    }
  }
  return { adminNotified: Boolean(alert.notifiedGeneration === alert.generation || claim) };
}

async function getWalletLedgerSummary(userId) {
  const [totals, first, last] = await Promise.all([
    WalletTransaction.aggregate([
      { $match: { userId } },
      { $group: {
        _id: null,
        transactionCount: { $sum: 1 },
        creditsNAD: { $sum: { $cond: [{ $eq: ['$type', 'seller_credit'] }, '$amountNAD', 0] } },
        debitsNAD: { $sum: { $cond: [{ $eq: ['$type', 'purchase_debit'] }, '$amountNAD', 0] } },
        refundsNAD: { $sum: { $cond: [{ $eq: ['$type', 'purchase_refund'] }, '$amountNAD', 0] } }
      } }
    ]),
    WalletTransaction.findOne({ userId }).sort({ createdAt: 1, _id: 1 })
      .select('type amountNAD balanceAfterNAD').lean(),
    WalletTransaction.findOne({ userId }).sort({ createdAt: -1, _id: -1 })
      .select('balanceAfterNAD').lean()
  ]);
  if (!totals.length || !first || !last) return null;
  return {
    ...totals[0],
    firstType: first.type,
    firstAmountNAD: first.amountNAD,
    firstBalanceAfterNAD: first.balanceAfterNAD,
    lastBalanceAfterNAD: last.balanceAfterNAD
  };
}

function calculateWalletPayment(totalNAD, walletBalanceNAD, paymentMethod) {
  const total = roundNAD(Number(totalNAD));
  const balance = roundNAD(Math.max(0, Number(walletBalanceNAD) || 0));
  const walletUsedNAD = paymentMethod === 'wallet' ? Math.min(balance, total) : 0;
  return { walletUsedNAD, cardDueNAD: roundNAD(total - walletUsedNAD) };
}

function isMatchingPromotionWalletDebit(campaign, transaction) {
  return Boolean(transaction
    && transaction.reference === `promotion:${campaign._id}`
    && transaction.type === 'purchase_debit'
    && transaction.userId.toString() === campaign.sellerId.toString()
    && transaction.amountNAD === campaign.walletUsedNAD);
}

function getPromotionPaymentIssue(campaign, walletTransaction) {
  if (campaign.status !== 'active') return null;
  const amountNAD = Number(campaign.amountNAD);
  const walletUsedNAD = Number(campaign.walletUsedNAD || 0);
  const cardDueNAD = Number(campaign.cardDueNAD || 0);
  if (!Number.isFinite(amountNAD) || amountNAD <= 0
    || !Number.isFinite(walletUsedNAD) || walletUsedNAD < 0
    || !Number.isFinite(cardDueNAD) || cardDueNAD < 0
    || roundNAD(walletUsedNAD + cardDueNAD) !== roundNAD(amountNAD)) {
    return 'the payment amounts do not match the promotion price';
  }
  if (!campaign.paidAt || !Number.isFinite(new Date(campaign.paidAt).getTime())) {
    return 'a completed payment timestamp is missing';
  }
  if (walletTransaction && !isMatchingPromotionWalletDebit(campaign, walletTransaction)) {
    return 'the Z-balance debit record does not match';
  }
  if (campaign.paymentMethod === 'wallet') {
    if (walletUsedNAD <= 0) return 'the selected Z-balance payment has no recorded debit amount';
    if (!isMatchingPromotionWalletDebit(campaign, walletTransaction)) return 'the Z-balance debit is missing';
    return null;
  }
  if (campaign.paymentMethod === 'card') {
    if (walletUsedNAD !== 0 || cardDueNAD <= 0 || walletTransaction) {
      return 'the recorded card payment details are inconsistent';
    }
    return null;
  }
  return 'the payment method is missing or cannot be verified';
}

function shouldCancelUnpaidPromotion(campaign, walletTransaction) {
  return getPromotionPaymentIssue(campaign, walletTransaction) !== null;
}

async function reconcileUnpaidPromotions(sellerId) {
  const campaigns = await PromotionCampaign.find({
    sellerId,
    status: 'active'
  }).select('_id sellerId productId status amountNAD paymentMethod walletUsedNAD cardDueNAD paidAt').lean();
  if (!campaigns.length) return 0;

  const references = campaigns.map((campaign) => `promotion:${campaign._id}`);
  const transactions = await WalletTransaction.find({ reference: { $in: references } })
    .select('reference userId type amountNAD').lean();
  const transactionsByReference = new Map(transactions.map((transaction) => [transaction.reference, transaction]));
  const products = await Product.find({ _id: { $in: campaigns.map((campaign) => campaign.productId) } })
    .select('_id title').lean();
  const productTitles = new Map(products.map((product) => [product._id.toString(), product.title]));
  let cancelledCount = 0;

  for (const campaign of campaigns) {
    const reference = `promotion:${campaign._id}`;
    const transaction = transactionsByReference.get(reference);
    const paymentIssue = getPromotionPaymentIssue(campaign, transaction);
    if (!paymentIssue) continue;

    const productTitle = productTitles.get(campaign.productId.toString()) || 'your product';
    const wasCancelled = await withMongoTransaction(async (session) => {
      const result = await PromotionCampaign.updateOne({
        _id: campaign._id,
        sellerId,
        status: 'active'
      }, { $set: { status: 'cancelled' } }, { session });
      if (!result.modifiedCount) return false;
      await SellerNotification.updateOne({
        userId: sellerId,
        promotionId: campaign._id,
        type: 'promotion_cancelled'
      }, {
        $setOnInsert: {
          title: 'Promotion removed',
          message: `The promotion for "${productTitle}" was removed because ${paymentIssue}. No additional Z-balance deduction was made. Contact support if you believe this is incorrect.`
        }
      }, { upsert: true, session });
      return true;
    });
    if (wasCancelled) cancelledCount += 1;
  }
  return cancelledCount;
}

function isAssistantPlanPaid(shop) {
  return Boolean(shop?.assistantPlanActive && shop?.assistantPlanPaidAt);
}

async function withMongoTransaction(operation) {
  const session = await mongoose.startSession();
  try {
    let result;
    await session.withTransaction(async () => {
      result = await operation(session);
    });
    return result;
  } finally {
    await session.endSession();
  }
}

async function applyWalletTransaction({
  userId,
  reference,
  type,
  amountNAD,
  orderNumber,
  description,
  session,
  insufficientBalanceMessage = 'Your Z balance changed. Refresh checkout and try again.'
}) {
  const existing = await WalletTransaction.findOne({ reference }).session(session);
  if (existing) {
    if (existing.userId.toString() !== userId.toString() || existing.type !== type || existing.amountNAD !== amountNAD) {
      throw new Error('Wallet transaction reference was already used for a different transaction.');
    }
    return existing;
  }

  const update = type === 'purchase_debit'
    ? { $inc: { walletBalanceNAD: -amountNAD } }
    : { $inc: { walletBalanceNAD: amountNAD } };
  const balanceCondition = type === 'purchase_debit'
    ? { $expr: { $gte: [{ $ifNull: ['$walletBalanceNAD', 0] }, amountNAD] } }
    : {};
  const user = await User.findOneAndUpdate(
    { _id: userId, ...balanceCondition },
    update,
    { returnDocument: 'after', session }
  );
  if (!user && type === 'purchase_debit') throw apiError(409, insufficientBalanceMessage);
  if (!user) throw new Error('Could not update the Z wallet for this transaction.');

  const [transaction] = await WalletTransaction.create([{
    userId,
    reference,
    type,
    amountNAD,
    balanceAfterNAD: roundNAD(user.walletBalanceNAD),
    orderNumber,
    description
  }], { session });
  return transaction;
}

function normalizeCartItems(rawItems) {
  if (!Array.isArray(rawItems) || rawItems.length === 0 || rawItems.length > 20) {
    throw apiError(400, 'Your cart must contain between 1 and 20 different products.');
  }

  const quantities = new Map();
  for (const item of rawItems) {
    if (!mongoose.isValidObjectId(item?.id) || !Number.isInteger(item?.quantity) || item.quantity < 1 || item.quantity > 99) {
      throw apiError(400, 'Your cart has an invalid product or quantity.');
    }
    const id = item.id.toString().toLowerCase();
    const quantity = (quantities.get(id) || 0) + item.quantity;
    if (quantity > 99) throw apiError(400, 'A product quantity cannot exceed 99.');
    quantities.set(id, quantity);
  }

  return [...quantities].map(([id, quantity]) => ({ id, quantity }));
}

function normalizeSavedCartItems(rawItems) {
  if (!Array.isArray(rawItems) || rawItems.length > 20) {
    throw apiError(400, 'Your cart can contain up to 20 different products.');
  }
  const seen = new Set();
  return rawItems.map((item) => {
    if (!mongoose.isValidObjectId(item?.id) || !Number.isInteger(item?.quantity) || item.quantity < 1 || item.quantity > 99) {
      throw apiError(400, 'Your cart has an invalid product or quantity.');
    }
    const id = item.id.toString().toLowerCase();
    if (seen.has(id)) throw apiError(400, 'Your cart contains a duplicate product.');
    seen.add(id);
    return { id, quantity: item.quantity };
  });
}

function normalizeSavedWishlistIds(rawIds) {
  if (!Array.isArray(rawIds) || rawIds.length > 500) {
    throw apiError(400, 'Your wishlist can contain up to 500 products.');
  }
  const seen = new Set();
  return rawIds.map((rawId) => {
    if (!mongoose.isValidObjectId(rawId)) throw apiError(400, 'Your wishlist contains an invalid product.');
    const id = rawId.toString().toLowerCase();
    if (seen.has(id)) throw apiError(400, 'Your wishlist contains a duplicate product.');
    seen.add(id);
    return id;
  });
}

function buildPromotionSchedule(startValue = new Date()) {
  const startsAt = new Date(startValue);
  if (!Number.isFinite(startsAt.getTime())) throw new Error('Promotion start date must be valid.');
  return {
    amountNAD: promotionPriceNAD,
    durationDays: promotionDurationDays,
    startsAt,
    expiresAt: new Date(startsAt.getTime() + promotionDurationDays * 24 * 60 * 60 * 1000)
  };
}

function normalizePromotionVisitorId(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.toLowerCase();
  if (!/^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/.test(normalized)) return null;
  return normalized.replaceAll('-', '');
}

function calculatePromotionClickThroughRate(impressions, clicks) {
  return impressions > 0 ? Math.round((clicks / impressions) * 10000) / 100 : 0;
}

function resolveShippingZone(sellerTown, deliveryTown) {
  if (sellerTown === deliveryTown) return 'local';
  if (hubTowns.has(sellerTown) && hubTowns.has(deliveryTown)) return 'hub';
  return 'remote';
}

async function buildOrderQuote(rawItems, deliveryTown) {
  if (!namibianTowns.includes(deliveryTown)) throw apiError(400, 'Choose a valid delivery town.');
  const requestedItems = normalizeCartItems(rawItems);
  const [unavailableShopIds, activeCommissionRate] = await Promise.all([
    getUnavailableShopIds(),
    getPlatformCommissionRate()
  ]);
  const products = await Product.find({
    _id: { $in: requestedItems.map((item) => item.id) },
    shopId: { $nin: unavailableShopIds },
    status: 'active',
    isAvailable: { $ne: false },
    reviewStatus: { $in: ['approved', null] },
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
    const commissionNAD = roundNAD(productsSubtotalNAD * activeCommissionRate);

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
      commissionRate: activeCommissionRate,
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
    commissionRate: activeCommissionRate,
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
      }, { $inc: { stock: -item.quantity } }, { returnDocument: 'after' });

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

function normalizeDuplicateText(value) {
  return value
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim();
}

function buildProductDuplicateKey({ title, description, category }) {
  return JSON.stringify([
    normalizeDuplicateText(title),
    normalizeDuplicateText(description),
    normalizeDuplicateText(category)
  ]);
}

function buildSellerMarketBenchmarks(categories, ownStats, marketStats) {
  const ownByCategory = new Map(ownStats.map((entry) => [entry._id, entry]));
  const marketByCategory = new Map(marketStats.map((entry) => [entry._id, entry]));
  return categories.map((category) => {
    const own = ownByCategory.get(category);
    const market = marketByCategory.get(category);
    return {
      category,
      ownProductCount: own?.productCount || 0,
      ownAveragePriceNAD: own ? Number(own.averagePriceNAD.toFixed(2)) : null,
      marketProductCount: market?.productCount || 0,
      competitorShopCount: market?.shopIds.length || 0,
      marketAveragePriceNAD: market ? Number(market.averagePriceNAD.toFixed(2)) : null
    };
  }).sort((a, b) => b.ownProductCount - a.ownProductCount || a.category.localeCompare(b.category));
}

async function findDuplicateShopName(nameKey) {
  if (await Shop.exists({ nameKey })) return true;
  const legacyShops = await Shop.find({ nameKey: { $exists: false } }).select('name').lean();
  return legacyShops.some((shop) => normalizeDuplicateText(shop.name) === nameKey);
}

async function findDuplicateProduct(shopId, duplicateKey, excludedProductId = null) {
  const duplicateFilter = { shopId, duplicateKey };
  if (excludedProductId) duplicateFilter._id = { $ne: excludedProductId };
  if (await Product.exists(duplicateFilter)) return true;

  const legacyFilter = { shopId, duplicateKey: { $exists: false } };
  if (excludedProductId) legacyFilter._id = { $ne: excludedProductId };
  const legacyProducts = await Product.find(legacyFilter).select('title description category').lean();
  return legacyProducts.some((product) => buildProductDuplicateKey(product) === duplicateKey);
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
    }, { $set: { paymentStatus: 'expired', reservationsReleasedAt: new Date() } }, { returnDocument: 'after' }).select('items');
    if (order) await releaseReservedStock(order.items);
  }
}

async function creditSellerWallet(orderId, sellerOrderId, now) {
  await withMongoTransaction(async (session) => {
    const order = await Order.findOne({ _id: orderId, paymentStatus: 'paid' }).session(session);
    const sellerOrder = order?.sellerOrders.find((entry) => entry._id.toString() === sellerOrderId.toString());
    const simulatedPayout = sellerOrder?.payoutStatus === 'paid'
      && typeof sellerOrder.payoutReference === 'string'
      && sellerOrder.payoutReference.startsWith('SIM-');
    if (!sellerOrder
      || sellerOrder.fulfillmentStatus !== 'delivered'
      || !sellerOrder.payoutEligibleAt
      || sellerOrder.payoutEligibleAt > now
      || (!['held', 'eligible'].includes(sellerOrder.payoutStatus) && !simulatedPayout)) return;
    if (sellerOrder.payoutStatus === 'eligible' && sellerOrder.walletCreditedAt) return;

    await applyWalletTransaction({
      userId: sellerOrder.sellerId,
      reference: `seller-credit:${order.orderNumber}:${sellerOrder._id}`,
      type: 'seller_credit',
      amountNAD: roundNAD(sellerOrder.payoutNAD),
      orderNumber: order.orderNumber,
      description: `Seller earnings for order ${order.orderNumber}`,
      session
    });

    const update = await Order.updateOne({
      _id: order._id,
      sellerOrders: { $elemMatch: {
        _id: sellerOrder._id,
        payoutStatus: sellerOrder.payoutStatus,
        ...(simulatedPayout ? { payoutReference: /^SIM-/ } : {})
      } }
    }, { $set: {
      'sellerOrders.$.payoutStatus': 'eligible',
      'sellerOrders.$.walletCreditedAt': sellerOrder.walletCreditedAt || now,
      ...(simulatedPayout ? { 'sellerOrders.$.payoutReference': '', 'sellerOrders.$.payoutMarkedAt': null } : {})
    } }, { session });
    if (!update.modifiedCount && !sellerOrder.walletCreditedAt) {
      throw new Error('Could not mark seller earnings as credited to the Z wallet.');
    }
  });
}

async function advancePayoutLifecycle() {
  const now = new Date();
  const orders = await Order.find({
    paymentStatus: 'paid',
    sellerOrders: { $elemMatch: {
      fulfillmentStatus: 'delivered',
      payoutEligibleAt: { $lte: now },
      $or: [
        { payoutStatus: { $in: ['held', 'eligible'] } },
        { payoutStatus: 'paid', payoutReference: /^SIM-/ }
      ]
    } }
  }).sort({ updatedAt: 1 }).limit(100).select('_id sellerOrders');

  const sellerIds = [...new Set(orders.flatMap((order) => order.sellerOrders
    .filter((sellerOrder) => sellerOrder.fulfillmentStatus === 'delivered'
      && (['held', 'eligible'].includes(sellerOrder.payoutStatus)
        || (sellerOrder.payoutStatus === 'paid' && typeof sellerOrder.payoutReference === 'string' && sellerOrder.payoutReference.startsWith('SIM-'))))
    .map((sellerOrder) => sellerOrder.sellerId.toString())))].map((id) => new mongoose.Types.ObjectId(id));
  const restrictedSellerIds = sellerIds.length
    ? new Set((await Shop.distinct('ownerId', {
      ownerId: { $in: sellerIds },
      $or: [
        { sellerSuspended: true },
        { sellerRestrictionStatus: 'banned' },
        { sellerRestrictionStatus: 'temp_hold', sellerRestrictedUntil: { $gt: now } }
      ]
    })).map((id) => id.toString()))
    : new Set();

  for (const order of orders) {
    for (const sellerOrder of order.sellerOrders) {
      if (restrictedSellerIds.has(sellerOrder.sellerId.toString())) continue;
      const currentStatus = sellerOrder.payoutStatus;
      const nextStatus = resolvePayoutStatus(sellerOrder, now);
      const simulatedPayout = currentStatus === 'paid'
        && typeof sellerOrder.payoutReference === 'string'
        && sellerOrder.payoutReference.startsWith('SIM-');
      if ((nextStatus === 'eligible' && ['held', 'eligible'].includes(currentStatus)) || simulatedPayout) {
        await creditSellerWallet(order._id, sellerOrder._id, now);
      }
    }
  }
}



app.post('/api/auth/register', async (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;
  const referralCode = typeof req.body?.referralCode === 'string' ? req.body.referralCode.trim().toUpperCase() : '';

  if (!name || name.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Enter a valid name and email, and a password between 8 and 128 characters.' });
  }
  if (referralCode && !/^[A-F0-9]{12}$/.test(referralCode)) {
    return res.status(400).json({ error: 'That referral code is not valid.' });
  }
  if (process.env.NODE_ENV === 'production' && (!passwordResetMailer || !resolveAppBaseUrl())) {
    return res.status(503).json({ error: 'Email verification is not configured. Contact Z support.' });
  }
  const referrer = referralCode ? await User.findOne({ referralCode }) : null;
  if (referralCode && !referrer) return res.status(400).json({ error: 'That referral code was not found.' });

  const salt = randomBytes(16).toString('hex');
  const passwordHash = (await scryptAsync(password, salt, 64)).toString('hex');
  let user;
  try {
    user = await User.create({
      name,
      email,
      role: process.env.NODE_ENV !== 'production'
        && isLocalMongoUri()
        && email === normalizeEmail(process.env.SANDBOX_EMAIL)
        ? 'sandbox'
        : 'customer',
      salt,
      passwordHash,
      referralCode: createReferralCode(),
      referredBy: referrer?._id || null
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ error: 'An account with that email already exists. Try signing in.' });
    }
    throw error;
  }

  await createSession(res, user);
  let verificationUrl = '';
  let verificationDeliveryFailed = false;
  try {
    verificationUrl = await createEmailVerification(user);
  } catch (error) {
    console.error('New account verification email could not be sent:', error.message);
    verificationDeliveryFailed = true;
  }

  return res.status(201).json({
    user: publicUser(user),
    verificationRequired: true,
    verificationUrl,
    message: verificationDeliveryFailed
      ? 'Your account was created, but the verification email could not be sent. Request a new link from your Profile.'
      : verificationUrl
        ? 'Open the verification link to verify your email before placing an order.'
        : 'We sent a verification link to your email. Verify it before placing an order.'
  });
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
  if (user.isSuspended) {
    const appealAccessToken = randomBytes(32).toString('hex');
    await SuspensionAppealAccess.findOneAndUpdate(
      { accountEmail: user.email },
      {
        $set: {
          verificationTokenHash: hashSessionToken(appealAccessToken),
          expiresAt: new Date(Date.now() + 10 * 60 * 1000)
        }
      },
      { upsert: true, returnDocument: 'after', runValidators: true, setDefaultsOnInsert: true }
    );
    return res.status(403).json({
      error: 'This account is suspended.',
      account_status: 'suspended',
      appeal_access_token: appealAccessToken
    });
  }

  const loginNetwork = await resolveLoginNetwork(req.ip);
  await createSession(res, user, () => LoginActivity.create({
    userId: user._id,
    device: describeLoginDevice(req.get('user-agent')),
    ...loginNetwork,
    expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
  }));
  return res.json({ user: publicUser(user) });
});

app.post('/api/auth/forgot-password', passwordResetRateLimit, async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (process.env.NODE_ENV === 'production' && (!passwordResetMailer || !resolveAppBaseUrl())) {
    return res.status(503).json({ error: 'Password reset email is not configured. Contact Z support.' });
  }
  const baseUrl = resolveAppBaseUrl();
  if (!baseUrl) return res.status(503).json({ error: 'The public application URL is not configured.' });

  const user = await User.findOne({ email }).select('_id email name');
  if (!user) return res.status(202).json({ message: 'If an account exists for that email, password reset instructions will be sent.' });

  const token = randomBytes(32).toString('hex');
  await PasswordReset.deleteMany({ userId: user._id });
  await PasswordReset.create({
    tokenHash: hashSessionToken(token),
    userId: user._id,
    expiresAt: new Date(Date.now() + 15 * 60 * 1000)
  });
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

app.post('/api/auth/verify-email/resend', emailVerificationRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to verify your email address.' });
  if (user.emailVerified) return res.status(409).json({ error: 'Your email address is already verified.' });
  try {
    const verificationUrl = await createEmailVerification(user);
    return res.json({
      message: 'A new verification link has been sent.',
      verificationUrl
    });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ error: error.message });
    console.error('Email verification delivery failed:', error.message);
    return res.status(503).json({ error: 'Could not send the verification email. Try again later.' });
  }
});

app.post('/api/auth/verify-email', async (req, res) => {
  const token = req.body?.token;
  if (!isValidEmailVerificationToken(token)) return res.status(400).json({ error: 'Use a valid email verification link.' });
  const verification = await EmailVerification.findOneAndDelete({
    tokenHash: hashSessionToken(token),
    expiresAt: { $gt: new Date() }
  });
  if (!verification) return res.status(400).json({ error: 'This email verification link is invalid or has expired. Request a new one.' });
  const user = await User.findById(verification.userId);
  if (!user) return res.status(400).json({ error: 'This email verification link is invalid or has expired. Request a new one.' });
  user.emailVerified = true;
  await user.save();
  await EmailVerification.deleteMany({ userId: user._id });
  return res.json({ ok: true, message: 'Your email is verified. You can now place an order.' });
});

app.patch('/api/account/profile', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to update your profile.' });
  const profile = normalizeProfileInput(req.body);
  user.name = profile.name;
  user.phone = profile.phone;
  user.town = profile.town;
  await user.save();
  return res.json({ user: publicUser(user) });
});

app.get('/api/account/referrals', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view referrals.' });
  if (!user.referralCode) {
    user.referralCode = createReferralCode();
    await user.save();
  }
  const referralCount = await User.countDocuments({ referredBy: user._id });
  const referralUrl = `/login?ref=${encodeURIComponent(user.referralCode)}`;
  return res.json({ referralCode: user.referralCode, referralUrl, referralCount, rewardsEnabled: false });
});

app.get('/api/auth/status', async (req, res) => {
  const user = await getSessionUser(req);
  return res.json({ user: user ? publicUser(user) : null });
});

app.get('/api/account/login-activity', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view account activity.' });
  const activities = await LoginActivity.find({
    userId: user._id,
    expiresAt: { $gt: new Date() }
  }).sort({ createdAt: -1 }).limit(10).select('device client_ip country_code city isp_provider readAt createdAt').lean();
  return res.json({
    activities: activities.map(({ _id, device, client_ip, country_code, city, isp_provider, readAt, createdAt }) => ({
      id: _id.toString(),
      device,
      client_ip,
      country_code,
      city,
      isp_provider,
      readAt,
      createdAt
    })),
    unreadCount: activities.filter((activity) => !activity.readAt).length
  });
});

app.post('/api/account/login-activity/read', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to update account activity.' });
  await LoginActivity.updateMany(
    { userId: user._id, readAt: null, expiresAt: { $gt: new Date() } },
    { $set: { readAt: new Date() } }
  );
  return res.json({ ok: true });
});

app.get('/api/account/seller-notifications', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view seller notifications.' });
  const notifications = await SellerNotification.find({ userId: user._id })
    .sort({ createdAt: -1 }).limit(50).select('title message promotionId readAt createdAt')
    .populate({ path: 'promotionId', select: 'productId' }).lean();
  return res.json({
    notifications: notifications.map((notification) => ({
      id: notification._id.toString(),
      title: notification.title,
      message: notification.message,
      productId: notification.promotionId?.productId?.toString() || null,
      readAt: notification.readAt,
      createdAt: notification.createdAt
    })),
    unreadCount: notifications.filter((notification) => !notification.readAt).length
  });
});

function notificationDestinationFilter(workspace) {
  const destinations = workspace === 'seller' ? ['seller', 'both'] : ['account', 'both'];
  return { $or: [{ destination: { $in: destinations } }, { destination: { $exists: false } }] };
}

app.get('/api/account/notifications', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view account notifications.' });
  const workspace = req.query.workspace || 'account';
  if (!['account', 'seller'].includes(workspace)) return res.status(400).json({ error: 'Choose the account or seller notification workspace.' });
  const destinationFilter = notificationDestinationFilter(workspace);
  const workspaceReadField = workspace === 'seller' ? 'sellerReadAt' : 'accountReadAt';
  const notificationQueries = [
    AccountNotification.find({ userId: user._id, ...destinationFilter })
      .sort({ createdAt: -1 }).limit(50).select(`title message ${workspaceReadField} readAt createdAt`).lean(),
    AccountNotification.countDocuments({
      userId: user._id,
      ...destinationFilter,
      [workspaceReadField]: null,
      readAt: null
    })
  ];
  if (workspace === 'seller') {
    notificationQueries.push(
      SellerNotification.find({ userId: user._id })
      .sort({ createdAt: -1 }).limit(50).select('title message promotionId readAt createdAt')
      .populate({ path: 'promotionId', select: 'productId' }).lean(),
      SellerNotification.countDocuments({ userId: user._id, readAt: null })
    );
  }
  const [accountNotifications, accountUnreadCount, sellerNotifications = [], sellerUnreadCount = 0] = await Promise.all(notificationQueries);
  const notifications = [
    ...accountNotifications.map((notification) => ({
      ...notification,
      readAt: notification[workspaceReadField] ?? notification.readAt,
      type: 'account'
    })),
    ...sellerNotifications.map((notification) => ({ ...notification, type: 'seller' }))
  ].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 50);
  return res.json({
    notifications: notifications.map((notification) => ({
      id: notification._id.toString(),
      type: notification.type,
      title: notification.title,
      message: notification.message,
      productId: notification.type === 'seller' ? notification.promotionId?.productId?.toString() || null : null,
      readAt: notification.readAt,
      createdAt: notification.createdAt
    })),
    unreadCount: accountUnreadCount + sellerUnreadCount
  });
});

app.post('/api/account/notifications/read', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to update account notifications.' });
  const workspace = req.query.workspace || 'account';
  if (!['account', 'seller'].includes(workspace)) return res.status(400).json({ error: 'Choose the account or seller notification workspace.' });
  const readAt = new Date();
  const workspaceReadField = workspace === 'seller' ? 'sellerReadAt' : 'accountReadAt';
  const updates = [
    AccountNotification.updateMany({
      userId: user._id,
      ...notificationDestinationFilter(workspace)
    }, { $set: { [workspaceReadField]: readAt } })
  ];
  if (workspace === 'seller') updates.push(SellerNotification.updateMany({ userId: user._id, readAt: null }, { $set: { readAt } }));
  await Promise.all(updates);
  return res.json({ ok: true });
});

app.post('/api/account/seller-notifications/read', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to update seller notifications.' });
  await SellerNotification.updateMany(
    { userId: user._id, readAt: null },
    { $set: { readAt: new Date() } }
  );
  return res.json({ ok: true });
});

app.get('/api/account/support-notifications', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view support notifications.' });
  if (!isModeratorUser(user) || isAdminUser(user)) return res.status(403).json({ error: 'Moderator access is required.' });
  const notifications = await SupportNotification.find({ userId: user._id })
    .populate({ path: 'supportRequestId', match: { category: 'general' }, select: 'category topic orderNumber status createdAt' })
    .sort({ createdAt: -1 })
    .limit(30)
    .lean();
  const visibleNotifications = notifications.filter((notification) => notification.supportRequestId);
  return res.json({
    notifications: visibleNotifications.map((notification) => ({
      id: notification._id.toString(),
      topic: notification.supportRequestId.topic,
      orderNumber: notification.supportRequestId.orderNumber,
      status: notification.supportRequestId.status,
      readAt: notification.readAt,
      createdAt: notification.createdAt
    })),
    unreadCount: visibleNotifications.filter((notification) => !notification.readAt).length
  });
});

app.post('/api/account/support-notifications/read', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to update support notifications.' });
  if (!isModeratorUser(user) || isAdminUser(user)) return res.status(403).json({ error: 'Moderator access is required.' });
  const notifications = await SupportNotification.find({ userId: user._id })
    .populate({ path: 'supportRequestId', match: { category: 'general' }, select: '_id' })
    .select('_id supportRequestId')
    .lean();
  await SupportNotification.updateMany({
    _id: { $in: notifications.filter((notification) => notification.supportRequestId).map((notification) => notification._id) },
    userId: user._id,
    readAt: null
  }, { $set: { readAt: new Date() } });
  return res.json({ ok: true });
});

app.get('/api/account/cart', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to sync your cart.' });
  return res.json({
    items: (user.cartItems || []).map(({ productId, quantity }) => ({
      id: productId.toString(),
      quantity
    }))
  });
});

app.put('/api/account/cart', cartWriteRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to sync your cart.' });
  const items = normalizeSavedCartItems(req.body?.items);
  user.cartItems = items.map(({ id, quantity }) => ({ productId: id, quantity }));
  await user.save();
  return res.json({
    items: user.cartItems.map(({ productId, quantity }) => ({
      id: productId.toString(),
      quantity
    }))
  });
});

app.get('/api/account/wishlist', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view your wishlist.' });
  const ids = (user.wishlistProductIds || []).map((id) => id.toString());
  const unavailableShopIds = await getUnavailableShopIds();
  const products = ids.length ? await Product.find({
    _id: { $in: ids },
    shopId: { $nin: unavailableShopIds },
    status: 'active',
    isAvailable: { $ne: false },
    reviewStatus: { $in: ['approved', null] },
    moderationStatus: { $ne: 'hidden' }
  }).populate('shopId', 'name slug sellerSuspended approvalStatus').lean() : [];
  const productsById = new Map(products
    .filter((product) => product.shopId && !product.shopId.sellerSuspended && !['pending', 'rejected'].includes(product.shopId.approvalStatus))
    .map((product) => [product._id.toString(), product]));
  return res.json({
    ids,
    products: ids.flatMap((id) => {
      const product = productsById.get(id);
      if (!product) return [];
      return [{
        id,
        title: product.title,
        description: product.description,
        priceNAD: product.priceNAD,
        category: product.category,
        town: product.town,
        imageUrl: product.imageUrl || '',
        shopName: product.shopId.name,
        shopSlug: product.shopId.slug
      }];
    })
  });
});

app.put('/api/account/wishlist', wishlistWriteRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to save your wishlist.' });
  const ids = normalizeSavedWishlistIds(req.body?.ids);
  user.wishlistProductIds = ids;
  await user.save();
  return res.json({ ids: user.wishlistProductIds.map((id) => id.toString()) });
});

app.post('/api/account/wishlist/:id', wishlistWriteRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to save your wishlist.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Choose a valid product.' });
  const productId = new mongoose.Types.ObjectId(req.params.id);
  await User.updateOne({
    _id: user._id,
    $expr: { $lt: [{ $size: { $ifNull: ['$wishlistProductIds', []] } }, 500] }
  }, { $addToSet: { wishlistProductIds: productId } });
  const updatedUser = await User.findById(user._id).select('wishlistProductIds').lean();
  const ids = (updatedUser?.wishlistProductIds || []).map((id) => id.toString());
  if (!ids.includes(productId.toString())) {
    return res.status(409).json({ error: 'Your wishlist can contain up to 500 products.' });
  }
  return res.json({ ids });
});

app.delete('/api/account/wishlist/:id', wishlistWriteRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to update your wishlist.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Choose a valid product.' });
  await User.updateOne(
    { _id: user._id },
    { $pull: { wishlistProductIds: new mongoose.Types.ObjectId(req.params.id) } }
  );
  const updatedUser = await User.findById(user._id).select('wishlistProductIds').lean();
  return res.json({ ids: (updatedUser?.wishlistProductIds || []).map((id) => id.toString()) });
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
    commissionRate: quote.commissionRate,
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
    totalNAD: quote.totalNAD,
    walletBalanceNAD: roundNAD(user.walletBalanceNAD || 0)
  });
});

app.get('/api/wallet', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view your Z balance.' });
  const transactions = await WalletTransaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(50).lean();
  return res.json({
    balanceNAD: roundNAD(user.walletBalanceNAD || 0),
    transactions: transactions.map((transaction) => ({
      type: transaction.type,
      amountNAD: transaction.amountNAD,
      balanceAfterNAD: transaction.balanceAfterNAD,
      orderNumber: transaction.orderNumber,
      description: transaction.description,
      createdAt: transaction.createdAt
    }))
  });
});

async function settleOrderPayment(orderNumber, buyerId, payment) {
  const orderSnapshot = await Order.findOne({ orderNumber, buyerId, paymentStatus: 'pending' });
  if (!orderSnapshot || orderSnapshot.reservationExpiresAt <= new Date() || orderSnapshot.reservationsReleasedAt) {
    throw apiError(409, 'This test payment is no longer pending. Create a new order.');
  }
  const shops = await Shop.find({ _id: { $in: orderSnapshot.sellerOrders.map((sellerOrder) => sellerOrder.shopId) } })
    .select('_id autoApprovalEnabled').lean();
  const autoApprovalByShop = new Map(shops.map((shop) => [shop._id.toString(), Boolean(shop.autoApprovalEnabled)]));

  return withMongoTransaction(async (session) => {
    const order = await Order.findOne({
      _id: orderSnapshot._id,
      buyerId,
      paymentStatus: 'pending',
      reservationExpiresAt: { $gt: new Date() },
      reservationsReleasedAt: null
    }).session(session);
    if (!order) throw apiError(409, 'This test payment is no longer pending. Create a new order.');

    if (order.walletUsedNAD > 0) {
      await applyWalletTransaction({
        userId: buyerId,
        reference: `purchase:${order.orderNumber}`,
        type: 'purchase_debit',
        amountNAD: order.walletUsedNAD,
        orderNumber: order.orderNumber,
        description: `Z balance used for order ${order.orderNumber}`,
        session
      });
    }

    const sellerOrders = order.sellerOrders.map((sellerOrder) => {
      const autoApprovalEnabled = autoApprovalByShop.get(sellerOrder.shopId.toString()) ?? false;
      const approvalStatus = resolveSellerApprovalState(autoApprovalEnabled);
      return {
        ...sellerOrder.toObject(),
        approvalStatus,
        fulfillmentStatus: approvalStatus === 'accepted' ? 'processing' : 'awaiting_payment',
        payoutStatus: 'held'
      };
    });
    const paidOrder = await Order.findOneAndUpdate({
      _id: order._id,
      buyerId,
      paymentStatus: 'pending',
      reservationExpiresAt: { $gt: new Date() },
      reservationsReleasedAt: null
    }, { $set: {
      paymentStatus: 'paid',
      paymentReference: payment?.reference || '',
      paidAt: payment?.confirmedAt || new Date(),
      sellerOrders
    } }, { returnDocument: 'after', session });
    if (!paidOrder) throw apiError(409, 'Order changed before the test payment was confirmed.');
    return paidOrder;
  });
}

app.post('/api/orders', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to place an order.' });
  if (!isEmailVerified(user)) return res.status(403).json({ error: 'Verify your email address in your account before placing an order.' });
  const paymentMethod = req.body?.paymentMethod ?? 'card';
  if (!['card', 'wallet'].includes(paymentMethod)) return res.status(400).json({ error: 'Choose card or Z balance at checkout.' });
  await releaseExpiredReservations();
  const quote = await buildOrderQuote(req.body?.items, req.body?.deliveryTown);
  const { walletUsedNAD, cardDueNAD } = calculateWalletPayment(quote.totalNAD, user.walletBalanceNAD, paymentMethod);
  if (paymentMethod === 'wallet' && walletUsedNAD <= 0) {
    return res.status(409).json({ error: 'Your Z balance is empty. Choose card checkout instead.' });
  }
  if (cardDueNAD > 0 && !mockPaymentsEnabled) {
    return res.status(503).json({ error: 'Test card checkout is disabled. A live card provider is not configured.' });
  }
  await reserveOrderStock(quote.items);

  const orderNumber = `Z-${Date.now()}-${randomBytes(2).toString('hex').toUpperCase()}`;
  const paymentIntent = cardDueNAD > 0 ? paymentAdapter.createIntent(orderNumber) : null;
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
      commissionRate: quote.commissionRate,
      totalNAD: quote.totalNAD,
      paymentMethod,
      walletUsedNAD,
      cardDueNAD,
      paymentMode: 'mock',
      paymentReference: paymentIntent?.reference || '',
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
    paymentMethod: order.paymentMethod,
    walletUsedNAD: order.walletUsedNAD,
    cardDueNAD: order.cardDueNAD,
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
  await releaseExpiredReservations();

  const order = await Order.findOne({ orderNumber: req.params.orderNumber, buyerId: user._id });
  if (!order) return res.status(404).json({ error: 'Order not found.' });
  if (order.paymentStatus !== 'pending' || order.reservationExpiresAt <= new Date()) {
    return res.status(409).json({ error: 'This test payment is no longer pending. Create a new order.' });
  }
  let payment = null;
  if (order.cardDueNAD > 0) {
    if (!mockPaymentsEnabled) return res.status(503).json({ error: 'Test card checkout is disabled. A live card provider is not configured.' });
    payment = paymentAdapter.confirmIntent(order.paymentReference);
  }
  const paidOrder = await settleOrderPayment(order.orderNumber, user._id, payment);
  const message = order.cardDueNAD > 0
    ? `Test card payment of N$ ${order.cardDueNAD.toFixed(2)} recorded${order.walletUsedNAD > 0 ? ` with N$ ${order.walletUsedNAD.toFixed(2)} from your Z balance` : ''}. No money was charged.`
    : `N$ ${order.walletUsedNAD.toFixed(2)} paid from your Z balance. No money left Z Namibia.`;
  return res.json({
    orderNumber: paidOrder.orderNumber,
    paymentStatus: paidOrder.paymentStatus,
    paymentMethod: paidOrder.paymentMethod,
    walletUsedNAD: paidOrder.walletUsedNAD,
    cardDueNAD: paidOrder.cardDueNAD,
    mock: order.cardDueNAD > 0,
    message
  });
});

app.get('/api/orders/mine', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view orders.' });
  await releaseExpiredReservations();
  const orders = await Order.find({ buyerId: user._id }).sort({ createdAt: -1 }).lean();
  const supportRequests = await SupportRequest.find({ buyerId: user._id }).sort({ createdAt: -1 }).lean();
  const requestsByOrder = new Map();
  supportRequests.forEach((request) => {
    if (!request.orderId) return;
    const key = request.orderId.toString();
    if (!requestsByOrder.has(key)) requestsByOrder.set(key, []);
    requestsByOrder.get(key).push({
      id: request._id.toString(),
      category: request.category || getSupportCategory(request.topic),
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

app.get('/api/support/requests/mine', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view your support requests.' });
  const requests = await SupportRequest.find({ buyerId: user._id }).sort({ createdAt: -1 }).limit(100).lean();
  return res.json({ requests: requests.map((request) => ({
    id: request._id.toString(),
    category: request.category || getSupportCategory(request.topic),
    orderNumber: request.orderNumber || '',
    topic: request.topic,
    message: request.message,
    status: request.status,
    adminResponse: request.adminResponse,
    createdAt: request.createdAt,
    updatedAt: request.updatedAt
  })) });
});

app.post('/api/support/requests', supportRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to contact support.' });
  const { topic, message } = normalizeSupportRequest(req.body);
  const orderNumber = typeof req.body?.orderNumber === 'string' ? req.body.orderNumber.trim() : '';
  if (orderNumber.length > 40) return res.status(400).json({ error: 'Order number must be 40 characters or fewer.' });
  const order = orderNumber
    ? await Order.findOne({ orderNumber, buyerId: user._id }).select('_id orderNumber')
    : null;
  if (orderNumber && !order) return res.status(404).json({ error: 'Order not found in your account.' });
  const request = await SupportRequest.create({
    orderId: order?._id || null,
    orderNumber: order?.orderNumber || '',
    buyerId: user._id,
    topic,
    category: getSupportCategory(topic),
    message
  });
  let notificationWarning = '';
  try {
    const notifiedModerators = await notifyModeratorsOfSupportRequest(request);
    if (request.category === 'general' && !notifiedModerators) {
      notificationWarning = 'Your request was saved, but no verified moderators are assigned to review general support yet.';
    }
  } catch (error) {
    console.error(`Support request ${request._id} was saved, but moderator notifications failed:`, error.message);
    notificationWarning = 'Your request was saved, but moderators could not be notified. Please check back for a response.';
  }
  return res.status(201).json({ request: {
    id: request._id.toString(),
    category: request.category,
    orderNumber: request.orderNumber,
    topic: request.topic,
    message: request.message,
    status: request.status,
    adminResponse: request.adminResponse,
    createdAt: request.createdAt,
    updatedAt: request.updatedAt
  }, notificationWarning });
});

app.post('/api/suspension-appeals', suspensionAppealRateLimit, async (req, res) => {
  const appeal = normalizeSuspensionAppeal(req.body);
  const verificationToken = typeof req.body?.verificationToken === 'string' ? req.body.verificationToken : '';
  if (!/^[a-f0-9]{64}$/.test(verificationToken)) {
    return res.status(403).json({ error: 'Sign in with the suspended account before submitting an appeal.' });
  }
  const verification = await SuspensionAppealAccess.findOneAndDelete({
    accountEmail: appeal.accountEmail,
    verificationTokenHash: hashSessionToken(verificationToken),
    expiresAt: { $gt: new Date() }
  }).lean();
  if (!verification) {
    return res.status(403).json({ error: 'Your sign-in verification expired. Sign in with the suspended account again before submitting.' });
  }

  const activeAppeal = await SuspensionAppeal.findOne({
    accountEmail: appeal.accountEmail,
    status: { $in: ['open', 'in_review'] }
  }).select('status createdAt').lean();
  if (activeAppeal) {
    return res.status(409).json({
      error: 'You already have an appeal awaiting review. No second request was submitted.',
      appeal: { status: activeAppeal.status, createdAt: activeAppeal.createdAt }
    });
  }
  try {
    await SuspensionAppeal.create({
      ...appeal,
      activeEmailKey: appeal.accountEmail
    });
  } catch (error) {
    if (error.code !== 11000) throw error;
    const duplicateAppeal = await SuspensionAppeal.findOne({
      accountEmail: appeal.accountEmail,
      status: { $in: ['open', 'in_review'] }
    }).select('status createdAt').lean();
    if (!duplicateAppeal) throw error;
    return res.status(409).json({
      error: 'You already have an appeal awaiting review. No second request was submitted.',
      appeal: { status: duplicateAppeal.status, createdAt: duplicateAppeal.createdAt }
    });
  }
  return res.status(201).json({
    ok: true,
    message: 'Your appeal has been submitted and is waiting for review. Submission is not approval, and your account remains suspended until a decision changes its status.'
  });
});

app.post('/api/suspension-appeals/status', async (req, res) => {
  const { accountEmail, verificationToken } = normalizeSuspensionAppealStatusAccess(req.body);
  const now = new Date();
  const verifiedAccess = await SuspensionAppealAccess.findOne({
    accountEmail,
    verificationTokenHash: hashSessionToken(verificationToken),
    expiresAt: { $gt: now },
  }).select('_id').lean();
  if (!verifiedAccess) {
    return res.status(403).json({ error: 'Your sign-in verification expired. Sign in with the suspended account again.' });
  }

  const appeal = await SuspensionAppeal.findOne({ accountEmail }).sort({ createdAt: -1 }).select('status createdAt').lean();
  return res.json({
    hasAppeal: Boolean(appeal),
    appeal: appeal ? { status: appeal.status, createdAt: appeal.createdAt } : null
  });
});

app.get('/api/admin/suspension-appeals', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is not configured for this account.' });
  const appeals = await SuspensionAppeal.find().sort({ status: 1, createdAt: 1 }).limit(200).lean();
  const accounts = appeals.length
    ? await User.find({ email: { $in: appeals.map((appeal) => appeal.accountEmail) } }).select('email isSuspended').lean()
    : [];
  const accountByEmail = new Map(accounts.map((account) => [account.email, account]));
  return res.json({ appeals: appeals.map((appeal) => ({
    id: appeal._id.toString(),
    accountEmail: appeal.accountEmail,
    accountId: accountByEmail.get(appeal.accountEmail)?._id.toString() || null,
    accountSuspended: Boolean(accountByEmail.get(appeal.accountEmail)?.isSuspended),
    reason: appeal.reason,
    referenceId: appeal.referenceId,
    triage: getSupportTriage('account_reinstatement', appeal.reason),
    status: appeal.status,
    createdAt: appeal.createdAt,
    updatedAt: appeal.updatedAt
  })) });
});

app.patch('/api/admin/suspension-appeals/:id', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Appeal not found.' });
  let review;
  try {
    review = normalizeSuspensionAppealReview(req.body);
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ error: error.message });
    throw error;
  }
  const { status, reactivateAccount } = review;
  const appeal = await SuspensionAppeal.findById(req.params.id);
  if (!appeal) return res.status(404).json({ error: 'Appeal not found.' });
  let account = null;
  let accountReactivated = false;
  if (reactivateAccount) {
    account = await User.findOne({ email: appeal.accountEmail });
    if (!account) return res.status(404).json({ error: 'No account exists for the email on this appeal.' });
    if (isConfiguredAdminIdentity(account)) return res.status(403).json({ error: 'The configured super-admin account cannot be reactivated through an appeal.' });
    accountReactivated = Boolean(account.isSuspended);
  }
  if (status !== 'resolved') {
    const otherActiveAppeal = await SuspensionAppeal.findOne({
      _id: { $ne: appeal._id },
      accountEmail: appeal.accountEmail,
      status: { $in: ['open', 'in_review'] }
    }).select('_id').lean();
    if (otherActiveAppeal) return res.status(409).json({ error: 'Another active appeal already exists for this account email.' });
    appeal.activeEmailKey = appeal.accountEmail;
  } else {
    appeal.activeEmailKey = undefined;
  }
  appeal.status = status;
  if (account?.isSuspended) {
    account.isSuspended = false;
    await account.save();
  }
  try {
    await appeal.save();
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'Another active appeal already exists for this account email.' });
    throw error;
  }
  if (accountReactivated && account) {
    await recordModerationAudit({
      actorId: user._id,
      action: 'account_reactivated',
      targetType: 'account',
      targetId: account._id.toString(),
      targetLabel: `${account.name} (${account.email})`,
      details: `Account reactivated while resolving suspension appeal ${appeal._id.toString()}.`
    });
  }
  return res.json({
    ok: true,
    status: appeal.status,
    accountReactivated
  });
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
    category: getSupportCategory(topic),
    message
  });
  let notificationWarning = '';
  try {
    const notifiedModerators = await notifyModeratorsOfSupportRequest(request);
    if (request.category === 'general' && !notifiedModerators) {
      notificationWarning = 'Your request was saved, but no verified moderators are assigned to review general support yet.';
    }
  } catch (error) {
    console.error(`Support request ${request._id} was saved, but moderator notifications failed:`, error.message);
    notificationWarning = 'Your request was saved, but moderators could not be notified. Please check back for a response.';
  }
  return res.status(201).json({ request: {
    id: request._id.toString(),
    category: request.category,
    topic: request.topic,
    message: request.message,
    status: request.status,
    adminResponse: request.adminResponse,
    createdAt: request.createdAt,
    updatedAt: request.updatedAt
  }, notificationWarning });
});

app.use('/api/seller', async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user) return next();
  if (!isEmailVerified(user)) {
    return res.status(403).json({
      error: 'Verify your email address to create or access a seller account.',
      verificationRequired: true
    });
  }
  if (await isSellerSuspended(user)) {
    if (req.method === 'GET' && req.path === '/shop') return next();
    return res.status(403).json({ error: 'Seller access is suspended. Buyer access to your account is still available.' });
  }
  return next();
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
      payoutMode: 'wallet'
    })));
  return res.json({ sellerOrders });
});

app.get('/api/seller/market-benchmarks', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view seller market benchmarks.' });
  const shop = await Shop.findOne({ ownerId: user._id }).select('_id').lean();
  if (!shop) return res.status(404).json({ error: 'Create your storefront before viewing market benchmarks.' });

  const activeListingFilter = { status: 'active', isAvailable: { $ne: false }, reviewStatus: { $in: ['approved', null] }, moderationStatus: { $ne: 'hidden' } };
  const ownStats = await Product.aggregate([
    { $match: { ...activeListingFilter, shopId: shop._id } },
    { $group: { _id: '$category', productCount: { $sum: 1 }, averagePriceNAD: { $avg: '$priceNAD' } } }
  ]);
  const categories = ownStats.map((entry) => entry._id);
  if (!categories.length) return res.json({ benchmarks: [] });

  const unavailableShopIds = await getUnavailableShopIds();
  const marketStats = await Product.aggregate([
    { $match: { ...activeListingFilter, category: { $in: categories }, shopId: { $nin: [...unavailableShopIds, shop._id] } } },
    { $group: {
      _id: '$category',
      productCount: { $sum: 1 },
      shopIds: { $addToSet: '$shopId' },
      averagePriceNAD: { $avg: '$priceNAD' }
    } }
  ]);
  return res.json({ benchmarks: buildSellerMarketBenchmarks(categories, ownStats, marketStats) });
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
  } }, { returnDocument: 'after' });
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
  }, { $set: { 'sellerOrders.$.fulfillmentStatus': 'shipped', 'sellerOrders.$.trackingReference': trackingReference } }, { returnDocument: 'after' });
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

  const cancelledOrder = await withMongoTransaction(async (session) => {
    if (order.paymentStatus === 'paid' && order.walletUsedNAD > 0) {
      await applyWalletTransaction({
        userId: user._id,
        reference: `refund:${order.orderNumber}`,
        type: 'purchase_refund',
        amountNAD: order.walletUsedNAD,
        orderNumber: order.orderNumber,
        description: `Z balance refund for cancelled order ${order.orderNumber}`,
        session
      });
    }
    const updatedOrder = await Order.findOneAndUpdate({
      _id: order._id,
      buyerId: user._id,
      paymentStatus: { $in: ['pending', 'paid'] }
    }, { $set: update }, { returnDocument: 'after', session });
    if (!updatedOrder) throw apiError(409, 'This order changed before it could be cancelled.');
    return updatedOrder;
  });

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
  } }, { returnDocument: 'after' });
  if (!order) return res.status(404).json({ error: 'A shipped seller order was not found.' });
  return res.json({ orderNumber: order.orderNumber, fulfillmentStatus: 'delivered', payoutStatus: 'held', payoutEligibleAt });
});

app.get('/api/seller/payout-ledger', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view seller balances.' });
  const cancelledUnpaidPromotions = await reconcileUnpaidPromotions(user._id);
  await advancePayoutLifecycle();
  const shop = await Shop.findOne({ ownerId: user._id })
    .select('sellerSuspended sellerRestrictionStatus sellerRestrictedUntil').lean();
  const payoutRestricted = isSellerInventoryRestricted(shop);
  const updatedUser = await User.findById(user._id).select('walletBalanceNAD').lean();
  const orders = await Order.find({ 'sellerOrders.sellerId': user._id, paymentStatus: 'paid' }).sort({ createdAt: -1 }).lean();
  const walletTransactions = await WalletTransaction.find({
    userId: user._id,
    type: { $in: ['purchase_debit', 'purchase_refund'] }
  }).sort({ createdAt: -1 }).limit(50).lean();
  const now = new Date();
  const entries = orders.flatMap((order) => order.sellerOrders
    .filter((sellerOrder) => sellerOrder.sellerId.toString() === user._id.toString())
    .map((sellerOrder) => ({
      orderNumber: order.orderNumber,
      shopName: sellerOrder.shopName,
      payoutNAD: sellerOrder.payoutNAD,
      payoutStatus: payoutRestricted && !sellerOrder.walletCreditedAt && sellerOrder.payoutStatus !== 'paid'
        ? 'held'
        : resolvePayoutStatus(sellerOrder, now),
      payoutEligibleAt: sellerOrder.payoutEligibleAt,
      walletCreditedAt: sellerOrder.walletCreditedAt,
      payoutMarkedAt: sellerOrder.payoutMarkedAt,
      createdAt: order.createdAt,
      payoutReference: sellerOrder.payoutReference,
      simulated: typeof sellerOrder.payoutReference === 'string' && sellerOrder.payoutReference.startsWith('SIM-')
    })));
  return res.json({
    entries,
    walletTransactions: walletTransactions.map((transaction) => ({
      type: transaction.type,
      amountNAD: transaction.amountNAD,
      balanceAfterNAD: transaction.balanceAfterNAD,
      orderNumber: transaction.orderNumber,
      description: transaction.description,
      createdAt: transaction.createdAt
    })),
    walletBalanceNAD: roundNAD(updatedUser?.walletBalanceNAD || 0),
    cancelledUnpaidPromotions,
    mode: 'wallet'
  });
});

app.post('/api/seller/statements', sellerStatementRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to generate a Z-balance statement.' });
  const key = getStatementSigningKey(process.env.Z_STATEMENT_SIGNING_KEY);
  if (!key) {
    return res.status(503).json({ error: 'Signed statements are unavailable until Z_STATEMENT_SIGNING_KEY is configured with a 32-byte hexadecimal key.' });
  }
  const shop = await Shop.findOne({ ownerId: user._id })
    .select('name sellerSuspended sellerRestrictionStatus sellerRestrictedUntil').lean();
  if (!shop) return res.status(404).json({ error: 'Seller shop not found.' });
  const payoutRestricted = isSellerInventoryRestricted(shop);
  const baseUrl = resolveAppBaseUrl();
  if (!baseUrl) return res.status(503).json({ error: 'The public application URL is not configured for statement verification.' });

  await reconcileUnpaidPromotions(user._id);
  await advancePayoutLifecycle();
  const [account, orders, walletTransactions] = await Promise.all([
    User.findById(user._id).select('walletBalanceNAD').lean(),
    Order.find({ 'sellerOrders.sellerId': user._id, paymentStatus: 'paid' }).sort({ createdAt: -1 }).lean(),
    WalletTransaction.find({
      userId: user._id,
      type: { $in: ['purchase_debit', 'purchase_refund'] }
    }).sort({ createdAt: -1 }).limit(50).lean()
  ]);
  const now = new Date();
  const entries = orders.flatMap((order) => order.sellerOrders
    .filter((sellerOrder) => sellerOrder.sellerId.toString() === user._id.toString())
    .map((sellerOrder) => ({
      orderNumber: order.orderNumber,
      shopName: sellerOrder.shopName,
      payoutNAD: sellerOrder.payoutNAD,
      payoutStatus: payoutRestricted && !sellerOrder.walletCreditedAt && sellerOrder.payoutStatus !== 'paid'
        ? 'held'
        : resolvePayoutStatus(sellerOrder, now),
      payoutEligibleAt: sellerOrder.payoutEligibleAt || null,
      walletCreditedAt: sellerOrder.walletCreditedAt || null,
      payoutMarkedAt: sellerOrder.payoutMarkedAt || null,
      createdAt: order.createdAt,
      simulated: typeof sellerOrder.payoutReference === 'string' && sellerOrder.payoutReference.startsWith('SIM-')
    })));
  const statement = {
    version: 1,
    issuer: 'Z Namibia',
    statementId: randomUUID(),
    issuedAt: now,
    shopName: shop.name,
    walletBalanceNAD: roundNAD(account?.walletBalanceNAD || 0),
    entries,
    walletTransactions: walletTransactions.map((transaction) => ({
      type: transaction.type,
      amountNAD: transaction.amountNAD,
      balanceAfterNAD: transaction.balanceAfterNAD,
      orderNumber: transaction.orderNumber,
      description: transaction.description,
      createdAt: transaction.createdAt
    })),
    walletTransactionLimit: 50
  };
  const signature = signStatement(statement, key);
  await SellerStatement.create({
    statementId: statement.statementId,
    userId: user._id,
    snapshot: statement,
    signature
  });
  return res.status(201).json({
    statement,
    signature,
    verificationUrl: `${baseUrl}/statement-verification?id=${encodeURIComponent(statement.statementId)}`
  });
});

app.get('/api/statements/:statementId/verify', async (req, res) => {
  const key = getStatementSigningKey(process.env.Z_STATEMENT_SIGNING_KEY);
  if (!key) {
    return res.status(503).json({ error: 'Statement verification is unavailable because the signing key is not configured.' });
  }
  if (!/^[\da-f-]{36}$/i.test(req.params.statementId)) {
    return res.status(400).json({ error: 'Invalid statement reference.' });
  }
  const record = await SellerStatement.findOne({ statementId: req.params.statementId }).lean();
  if (!record) return res.status(404).json({ error: 'No Z Namibia statement matches this reference.' });
  const verified = verifyStatement(record.snapshot, record.signature, key)
    && record.snapshot.statementId === record.statementId;
  if (!verified) return res.status(409).json({ error: 'This statement failed its authenticity check. Do not rely on it.' });
  return res.json({ verified: true, statement: record.snapshot, signature: record.signature });
});

app.get('/api/developer/apps', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to manage developer applications.' });
  if (!isEmailVerified(user)) return res.status(403).json({ error: 'Verify your email address before creating API credentials.' });
  const applications = await DeveloperApplication.find({ ownerId: user._id }).sort({ createdAt: -1 }).lean();
  return res.json({
    maxApplications: 5,
    applications: applications.map((application) => ({
      appId: application.appId,
      name: application.name,
      tokenLast4: application.tokenLast4,
      revokedAt: application.revokedAt,
      lastUsedAt: application.lastUsedAt,
      createdAt: application.createdAt
    }))
  });
});

app.post('/api/developer/apps', developerAppRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to create a developer application.' });
  if (!isEmailVerified(user)) return res.status(403).json({ error: 'Verify your email address before creating API credentials.' });
  const name = normalizeDeveloperAppName(req.body?.name);
  if (!name) return res.status(400).json({ error: 'Enter an application name between 1 and 80 characters.' });
  const applicationCount = await DeveloperApplication.countDocuments({ ownerId: user._id, revokedAt: null });
  if (applicationCount >= 5) return res.status(409).json({ error: 'Each developer account can have up to five applications.' });

  const credentials = createDeveloperCredentials();
  const application = await DeveloperApplication.create({
    ownerId: user._id,
    name,
    ...credentials
  });
  return res.status(201).json({
    application: {
      appId: application.appId,
      name: application.name,
      tokenLast4: application.tokenLast4,
      createdAt: application.createdAt
    },
    apiToken: credentials.token,
    warning: 'Copy this API token now. It cannot be viewed again; create a new application if it is lost.'
  });
});

app.delete('/api/developer/apps/:appId', developerAppRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to revoke a developer application.' });
  if (!/^[\da-f-]{36}$/i.test(req.params.appId)) {
    return res.status(404).json({ error: 'Developer application not found.' });
  }
  const application = await DeveloperApplication.findOneAndUpdate({
    ownerId: user._id,
    appId: req.params.appId,
    revokedAt: null
  }, { $set: { revokedAt: new Date() } }, { returnDocument: 'after' });
  if (!application) return res.status(404).json({ error: 'Active developer application not found.' });
  return res.json({ revoked: true, appId: application.appId });
});

app.get('/api/admin/developer-api/usage', async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) {
    return res.status(403).json({ error: 'Super Admin access is required.' });
  }
  const days = Number(req.query.days || 30);
  if (![7, 30, 90].includes(days)) {
    return res.status(400).json({ error: 'Choose a 7, 30, or 90 day reporting period.' });
  }

  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  const start = new Date(today.getTime() - (days - 1) * 24 * 60 * 60 * 1000);
  try {
    const records = await DeveloperApiUsage.aggregate([
      { $match: { day: { $gte: start, $lte: today } } },
      {
        $group: {
          _id: { day: '$day', endpoint: '$endpoint', appId: '$appId' },
          requests: { $sum: '$requests' },
          successes: { $sum: '$successes' },
          verified: { $sum: '$verified' },
          mismatched: { $sum: '$mismatched' },
          clientErrors: { $sum: '$clientErrors' },
          serverErrors: { $sum: '$serverErrors' },
          totalDurationMs: { $sum: '$totalDurationMs' }
        }
      },
      { $sort: { '_id.day': 1 } }
    ]);

    const dailyByDate = new Map();
    const endpoints = new Map();
    const applications = new Map();
    const totals = { requests: 0, successes: 0, verified: 0, mismatched: 0, clientErrors: 0, serverErrors: 0, totalDurationMs: 0 };
    for (let offset = 0; offset < days; offset += 1) {
      const day = new Date(start.getTime() + offset * 24 * 60 * 60 * 1000);
      dailyByDate.set(day.toISOString().slice(0, 10), {
        day: day.toISOString().slice(0, 10),
        requests: 0,
        verified: 0,
        mismatched: 0
      });
    }

    for (const record of records) {
      const dateKey = record._id.day.toISOString().slice(0, 10);
      const daily = dailyByDate.get(dateKey);
      if (daily) {
        daily.requests += record.requests;
        daily.verified += record.verified || 0;
        daily.mismatched += record.mismatched || 0;
      }
      for (const field of ['requests', 'successes', 'verified', 'mismatched', 'clientErrors', 'serverErrors', 'totalDurationMs']) {
        totals[field] += record[field] || 0;
      }
      const endpoint = endpoints.get(record._id.endpoint) || {
        endpoint: record._id.endpoint,
        requests: 0,
        successes: 0,
        verified: 0,
        mismatched: 0,
        clientErrors: 0,
        serverErrors: 0,
        totalDurationMs: 0
      };
      for (const field of ['requests', 'successes', 'verified', 'mismatched', 'clientErrors', 'serverErrors', 'totalDurationMs']) {
        endpoint[field] += record[field] || 0;
      }
      endpoints.set(record._id.endpoint, endpoint);
      if (record._id.appId) {
        const application = applications.get(record._id.appId) || {
          appId: record._id.appId,
          requests: 0,
          successes: 0,
          verified: 0,
          mismatched: 0,
          clientErrors: 0,
          serverErrors: 0,
          totalDurationMs: 0
        };
        for (const field of ['requests', 'successes', 'verified', 'mismatched', 'clientErrors', 'serverErrors', 'totalDurationMs']) {
          application[field] += record[field] || 0;
        }
        applications.set(record._id.appId, application);
      }
    }

    const topApplications = [...applications.values()]
      .sort((left, right) => right.requests - left.requests)
      .slice(0, 10);
    const applicationNames = await DeveloperApplication.find({
      appId: { $in: topApplications.map((application) => application.appId) }
    }).select('appId name').lean();
    const namesById = new Map(applicationNames.map((application) => [application.appId, application.name]));
    const activeApplications = await DeveloperApplication.countDocuments({
      revokedAt: null,
      lastUsedAt: { $gte: start }
    });

    return res.json({
      days,
      totals: {
        ...totals,
        averageDurationMs: totals.requests ? Math.round(totals.totalDurationMs / totals.requests) : 0,
        activeApplications
      },
      daily: [...dailyByDate.values()],
      endpoints: [...endpoints.values()]
        .sort((left, right) => right.requests - left.requests)
        .map((endpoint) => ({
          ...endpoint,
          averageDurationMs: endpoint.requests ? Math.round(endpoint.totalDurationMs / endpoint.requests) : 0
        })),
      applications: topApplications.map((application) => ({
        ...application,
        name: namesById.get(application.appId) || 'Revoked or unavailable application',
        averageDurationMs: application.requests ? Math.round(application.totalDurationMs / application.requests) : 0
      }))
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/developer/statements/verify-upload', statementApiRateLimit, async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to verify a statement PDF.' });
  if (!isEmailVerified(user)) return res.status(403).json({ error: 'Verify your email address before using developer tools.' });

  statementPdfUpload.single('statement')(req, res, async (uploadError) => {
    if (uploadError) return next(uploadError);
    try {
      const appId = typeof req.body?.appId === 'string' ? req.body.appId.trim() : '';
      if (!/^[\da-f-]{36}$/i.test(appId)) {
        return res.status(400).json({ error: 'Choose an active developer application.' });
      }
      const application = await DeveloperApplication.findOne({ appId, ownerId: user._id, revokedAt: null }).select('_id').lean();
      if (!application) return res.status(403).json({ error: 'Choose an active application owned by your developer account.' });
      if (!req.file || !req.file.buffer.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
        return res.status(400).json({ error: 'Upload a valid PDF statement.' });
      }

      const parser = new PDFParse({ data: req.file.buffer });
      let parsedText;
      try {
        const parsedPdf = await parser.getText();
        parsedText = parsedPdf.text;
      } catch {
        return res.status(400).json({ error: 'The uploaded PDF could not be read. Upload an unencrypted statement PDF.' });
      } finally {
        await parser.destroy();
      }
      const extractedStatementId = parsedText.match(/\b[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}\b/i)?.[0] || '';
      const providedStatementId = typeof req.body?.statementId === 'string' ? req.body.statementId.trim() : '';
      if (providedStatementId && !/^[\da-f-]{36}$/i.test(providedStatementId)) {
        return res.status(400).json({ error: 'The statement reference must be a valid reference ID.' });
      }
      if (providedStatementId && extractedStatementId && providedStatementId.toLowerCase() !== extractedStatementId.toLowerCase()) {
        return res.status(409).json({ verified: false, error: 'The supplied reference does not match the reference printed in the PDF.' });
      }
      const statementId = extractedStatementId || providedStatementId;
      if (!statementId) {
        return res.status(400).json({ error: 'No statement reference was found in the PDF. Enter it manually and try again.' });
      }
      const key = getStatementSigningKey(process.env.Z_STATEMENT_SIGNING_KEY);
      if (!key) return res.status(503).json({ error: 'Statement verification is temporarily unavailable.' });
      const record = await SellerStatement.findOne({ statementId }).lean();
      if (!record) return res.status(404).json({ verified: false, error: 'No Z Namibia statement matches the PDF reference.' });
      if (!verifyStatement(record.snapshot, record.signature, key) || record.snapshot.statementId !== record.statementId) {
        return res.status(409).json({ verified: false, error: 'The official statement record failed its signature check.' });
      }
      const checks = getStatementPdfChecks(record.snapshot, parsedText);
      const verified = checks.length > 0 && checks.every((check) => check.matched);
      return res.json({
        verified,
        recordVerified: true,
        statementId,
        message: verified
          ? 'The signed record is valid and the uploaded PDF text matches its statement values.'
          : 'The signed record is valid, but one or more uploaded PDF values do not match it.',
        checks
      });
    } catch (error) {
      return next(error);
    }
  });
});

app.get('/api/v1/statements/:statementId/verify', trackDeveloperApiUsage('reference'), statementApiRateLimit, async (req, res, next) => {
  const application = await authenticateDeveloperApplication(req, res);
  if (!application) return;
  if (!/^[\da-f-]{36}$/i.test(req.params.statementId)) {
    return res.status(400).json({ error: 'Invalid statement reference.' });
  }
  const key = getStatementSigningKey(process.env.Z_STATEMENT_SIGNING_KEY);
  if (!key) return res.status(503).json({ error: 'Statement verification is temporarily unavailable.' });
  try {
    const record = await SellerStatement.findOne({ statementId: req.params.statementId }).lean();
    if (!record) return res.status(404).json({ verified: false, error: 'No Z Namibia statement matches this reference.' });
    const verified = verifyStatement(record.snapshot, record.signature, key)
      && record.snapshot.statementId === record.statementId;
    if (!verified) {
      req.developerApiOutcome = 'mismatched';
      return res.status(409).json({ verified: false, error: 'The official statement record failed its signature check.' });
    }
    req.developerApiOutcome = 'verified';
    return res.json({ verified: true, statement: record.snapshot, signature: record.signature });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/v1/statements/verify-pdf', trackDeveloperApiUsage('pdf'), statementApiRateLimit, async (req, res, next) => {
  const application = await authenticateDeveloperApplication(req, res);
  if (!application) return;
  statementPdfUpload.single('statement')(req, res, async (uploadError) => {
    if (uploadError) return next(uploadError);
    try {
      if (!req.file || !req.file.buffer.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
        return res.status(400).json({ error: 'Upload a valid PDF statement.' });
      }
      const parser = new PDFParse({ data: req.file.buffer });
      let parsedText;
      try {
        const parsedPdf = await parser.getText();
        parsedText = parsedPdf.text;
      } catch {
        return res.status(400).json({ error: 'The uploaded PDF could not be read. Upload an unencrypted statement PDF.' });
      } finally {
        await parser.destroy();
      }
      const extractedStatementId = parsedText.match(/\b[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}\b/i)?.[0] || '';
      const providedStatementId = typeof req.body?.statementId === 'string' ? req.body.statementId.trim() : '';
      if (providedStatementId && !/^[\da-f-]{36}$/i.test(providedStatementId)) {
        return res.status(400).json({ error: 'The statement reference must be a valid reference ID.' });
      }
      if (providedStatementId && extractedStatementId && providedStatementId.toLowerCase() !== extractedStatementId.toLowerCase()) {
        req.developerApiOutcome = 'mismatched';
        return res.status(409).json({ verified: false, error: 'The supplied reference does not match the reference printed in the PDF.' });
      }
      const statementId = extractedStatementId || providedStatementId;
      if (!statementId) {
        return res.status(400).json({ error: 'No statement reference was found in the PDF. Provide statementId if it cannot be read.' });
      }
      const key = getStatementSigningKey(process.env.Z_STATEMENT_SIGNING_KEY);
      if (!key) return res.status(503).json({ error: 'Statement verification is temporarily unavailable.' });
      const record = await SellerStatement.findOne({ statementId }).lean();
      if (!record) return res.status(404).json({ verified: false, error: 'No Z Namibia statement matches the PDF reference.' });
      if (!verifyStatement(record.snapshot, record.signature, key) || record.snapshot.statementId !== record.statementId) {
        req.developerApiOutcome = 'mismatched';
        return res.status(409).json({ verified: false, error: 'The official statement record failed its signature check.' });
      }
      const checks = getStatementPdfChecks(record.snapshot, parsedText);
      const verified = checks.length > 0 && checks.every((check) => check.matched);
      req.developerApiOutcome = verified ? 'verified' : 'mismatched';
      return res.json({
        verified,
        recordVerified: true,
        statementId,
        message: verified
          ? 'The signed record is valid and the uploaded PDF text matches its statement values.'
          : 'The signed record is valid, but one or more uploaded PDF values do not match it.',
        checks
      });
    } catch (error) {
      return next(error);
    }
  });
});

app.post('/api/admin/statements/read-reference', adminStatementRateLimit, async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is required to read statement references.' });
  statementPdfUpload.single('statement')(req, res, async (uploadError) => {
    if (uploadError) return next(uploadError);
    if (!req.file || !req.file.buffer.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
      return res.status(400).json({ error: 'Upload a valid PDF statement.' });
    }
    const parser = new PDFParse({ data: req.file.buffer });
    try {
      const parsedPdf = await parser.getText();
      const statementId = parsedPdf.text.match(/\b[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}\b/i)?.[0] || '';
      if (!statementId) return res.status(422).json({ error: 'No statement reference could be read from this PDF.' });
      return res.json({ statementId });
    } catch {
      return res.status(400).json({ error: 'The uploaded PDF could not be read. Upload an unencrypted statement PDF.' });
    } finally {
      await parser.destroy();
    }
  });
});

app.post('/api/admin/statements/verify-upload', adminStatementRateLimit, async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is required to verify uploaded statements.' });
  const key = getStatementSigningKey(process.env.Z_STATEMENT_SIGNING_KEY);
  if (!key) return res.status(503).json({ error: 'Statement verification is unavailable because the signing key is not configured.' });

  statementPdfUpload.single('statement')(req, res, async (uploadError) => {
    if (uploadError) return next(uploadError);
    try {
      if (!req.file || !req.file.buffer.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
        return res.status(400).json({ error: 'Upload a valid PDF statement.' });
      }
      const providedStatementId = typeof req.body?.statementId === 'string' ? req.body.statementId.trim() : '';
      if (providedStatementId && !/^[\da-f-]{36}$/i.test(providedStatementId)) {
        return res.status(400).json({ error: 'The statement reference must be a valid reference ID.' });
      }

      const parser = new PDFParse({ data: req.file.buffer });
      let parsedText;
      try {
        const parsedPdf = await parser.getText();
        parsedText = parsedPdf.text;
      } catch {
        return res.status(400).json({ error: 'The uploaded PDF could not be read. Upload an unencrypted statement PDF.' });
      } finally {
        await parser.destroy();
      }
      const extractedStatementId = parsedText.match(/\b[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}\b/i)?.[0] || '';
      const statementId = providedStatementId || extractedStatementId;
      if (!statementId) {
        return res.status(400).json({ error: 'No statement reference was found in the PDF. Enter the reference manually and try again.' });
      }
      const record = await SellerStatement.findOne({ statementId }).lean();
      if (!record) return res.status(404).json({ error: 'No Z Namibia statement matches the reference found in the PDF.' });
      if (!verifyStatement(record.snapshot, record.signature, key) || record.snapshot.statementId !== record.statementId) {
        return res.status(409).json({ error: 'The official statement record failed its signature check.' });
      }
      const checks = getStatementPdfChecks(record.snapshot, parsedText);
      const matched = checks.length > 0 && checks.every((check) => check.matched);
      return res.json({
        verified: matched,
        recordVerified: true,
        message: matched
          ? 'The signed Z Namibia record is valid and the uploaded PDF text matches its statement values.'
          : 'The signed record is valid, but one or more uploaded PDF values do not match it.',
        statement: record.snapshot,
        signature: record.signature,
        checks
      });
    } catch (error) {
      return next(error);
    }
  });
});

app.get('/api/seller/payout-settings', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view payout settings.' });
  const shop = await Shop.findOne({ ownerId: user._id })
    .select('_id sellerSuspended sellerRestrictionStatus sellerRestrictedUntil').lean();
  if (!shop) return res.status(404).json({ error: 'Seller shop not found.' });
  const [account, requests] = await Promise.all([
    User.findById(user._id).select('walletBalanceNAD payoutBankAccount').lean(),
    SimulatedPayoutRequest.find({ userId: user._id }).sort({ createdAt: -1 }).limit(50).lean()
  ]);
  return res.json({
    simulated: true,
    walletBalanceNAD: roundNAD(account?.walletBalanceNAD || 0),
    payoutAccount: account?.payoutBankAccount?.accountLast4 ? {
      bankName: account.payoutBankAccount.bankName,
      accountName: account.payoutBankAccount.accountName,
      accountLast4: account.payoutBankAccount.accountLast4
    } : null,
    requests: requests.map((request) => ({
      id: request._id.toString(),
      amountNAD: request.amountNAD,
      status: request.status,
      mode: request.mode,
      destination: {
        bankName: request.destination.bankName,
        accountName: request.destination.accountName,
        accountLast4: request.destination.accountLast4
      },
      createdAt: request.createdAt
    }))
  });
});

app.put('/api/seller/payout-settings', sellerPayoutRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to save payout details.' });
  const shop = await Shop.findOne({ ownerId: user._id }).select('_id').lean();
  if (!shop) return res.status(404).json({ error: 'Seller shop not found.' });
  const normalized = normalizeBankPayoutAccount(req.body);
  if (normalized.error) return res.status(400).json({ error: normalized.error });

  const updatedUser = await User.findByIdAndUpdate(user._id, {
    $set: { payoutBankAccount: normalized.account }
  }, { returnDocument: 'after', runValidators: true }).select('payoutBankAccount').lean();
  if (!updatedUser) return res.status(404).json({ error: 'Seller account not found.' });
  return res.json({
    simulated: true,
    payoutAccount: {
      bankName: updatedUser.payoutBankAccount.bankName,
      accountName: updatedUser.payoutBankAccount.accountName,
      accountLast4: updatedUser.payoutBankAccount.accountLast4
    }
  });
});

app.post('/api/seller/payout-requests', sellerPayoutRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to create a payout request.' });
  const shop = await Shop.findOne({ ownerId: user._id })
    .select('_id sellerSuspended sellerRestrictionStatus sellerRestrictedUntil').lean();
  if (!shop) return res.status(404).json({ error: 'Seller shop not found.' });
  const restrictionError = sellerRestrictionError(shop);
  if (restrictionError) return res.status(403).json({ error: restrictionError });
  const account = await User.findById(user._id).select('walletBalanceNAD payoutBankAccount').lean();
  if (!account?.payoutBankAccount?.accountLast4) {
    return res.status(409).json({ error: 'Save a simulated bank payout destination first.' });
  }
  const normalized = normalizePayoutRequestAmount(req.body?.amountNAD, account.walletBalanceNAD);
  if (normalized.error) return res.status(400).json({ error: normalized.error });

  const request = await SimulatedPayoutRequest.create({
    userId: user._id,
    shopId: shop._id,
    amountNAD: normalized.amountNAD,
    status: 'simulated',
    mode: 'simulated',
    destination: {
      bankName: account.payoutBankAccount.bankName,
      accountName: account.payoutBankAccount.accountName,
      accountLast4: account.payoutBankAccount.accountLast4
    }
  });
  return res.status(201).json({
    simulated: true,
    fundsMoved: false,
    request: {
      id: request._id.toString(),
      amountNAD: request.amountNAD,
      status: request.status,
      createdAt: request.createdAt
    },
    message: 'Simulated request recorded. No funds were sent, reserved, or deducted.'
  });
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
  const sellerIds = [...new Set(orders.flatMap((order) => order.sellerOrders.map((sellerOrder) => sellerOrder.sellerId?._id?.toString()).filter(Boolean)))];
  const sellerShops = sellerIds.length
    ? await Shop.find({ ownerId: { $in: sellerIds } })
      .select('ownerId sellerSuspended sellerRestrictionStatus sellerRestrictedUntil').lean()
    : [];
  const restrictedSellerIds = new Set(sellerShops
    .filter((shop) => isSellerInventoryRestricted(shop, now))
    .map((shop) => shop.ownerId.toString()));
  const sellerRestrictionById = new Map(sellerShops.map((shop) => [shop.ownerId.toString(), shop]));
  const entries = orders.flatMap((order) => order.sellerOrders
    .filter((sellerOrder) => sellerOrder.fulfillmentStatus === 'delivered' && ['held', 'eligible', 'paid'].includes(sellerOrder.payoutStatus))
    .map((sellerOrder) => {
      const sellerId = sellerOrder.sellerId?._id?.toString() || sellerOrder.sellerId?.toString();
      const sellerRestriction = sellerRestrictionById.get(sellerId);
      const sellerRestricted = restrictedSellerIds.has(sellerId);
      return {
        orderNumber: order.orderNumber,
        sellerOrderId: sellerOrder._id.toString(),
        sellerName: sellerOrder.sellerId?.name || 'Seller account unavailable',
        sellerEmail: sellerOrder.sellerId?.email || '',
        shopName: sellerOrder.shopName,
        productsSubtotalNAD: sellerOrder.productsSubtotalNAD,
        shippingNAD: sellerOrder.shippingNAD,
        commissionNAD: sellerOrder.commissionNAD,
        payoutNAD: sellerOrder.payoutNAD,
        payoutStatus: sellerRestricted && !sellerOrder.walletCreditedAt && sellerOrder.payoutStatus !== 'paid' ? 'held' : sellerOrder.payoutStatus,
        payoutEligibleAt: sellerOrder.payoutEligibleAt,
        walletCreditedAt: sellerOrder.walletCreditedAt,
        payoutMarkedAt: sellerOrder.payoutMarkedAt,
        payoutReference: sellerOrder.payoutReference,
        eligible: Boolean(sellerOrder.walletCreditedAt) || (!sellerRestricted && (sellerOrder.payoutStatus === 'eligible' || sellerOrder.payoutStatus === 'paid')),
        sellerRestricted,
        sellerRestrictionStatus: sellerRestriction?.sellerRestrictionStatus || 'active',
        sellerRestrictedUntil: sellerRestriction?.sellerRestrictedUntil || null,
        simulated: simulatedPayoutsEnabled && sellerOrder.payoutStatus === 'paid'
      };
    }));
  return res.json({ entries, generatedAt: now, mode: 'wallet' });
});

app.get('/api/admin/support-requests', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });
  const visibilityFilter = getSupportRequestVisibilityFilter(isAdminUser(user));
  const requests = await SupportRequest.find(visibilityFilter).populate('buyerId', 'name email').sort({ status: 1, createdAt: 1 }).limit(200).lean();
  return res.json({ requests: requests.map((request) => ({
    id: request._id.toString(),
    category: request.category || getSupportCategory(request.topic),
    orderNumber: request.orderNumber,
    buyer: request.buyerId ? { name: request.buyerId.name, email: request.buyerId.email } : null,
    topic: request.topic,
    message: request.message,
    triage: getSupportTriage(request.topic, request.message),
    status: request.status,
    adminResponse: request.adminResponse,
    createdAt: request.createdAt,
    updatedAt: request.updatedAt
  })) });
});

app.patch('/api/admin/support-requests/:id', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Support request not found.' });
  const status = req.body?.status;
  const adminResponse = typeof req.body?.adminResponse === 'string' ? req.body.adminResponse.trim() : '';
  if (!['open', 'in_review', 'resolved'].includes(status) || adminResponse.length > 1000) {
    return res.status(400).json({ error: 'Choose a valid status and keep the response under 1000 characters.' });
  }
  const visibilityFilter = {
    _id: req.params.id,
    ...getSupportRequestVisibilityFilter(isAdminUser(user))
  };
  const request = await SupportRequest.findOne(visibilityFilter);
  if (!request) return res.status(404).json({ error: 'Support request not found.' });
  request.status = status;
  request.adminResponse = adminResponse;
  await request.save();
  return res.json({ ok: true, status: request.status, adminResponse: request.adminResponse });
});

app.post('/api/admin/payout-report/:orderNumber/:sellerOrderId/mark-paid', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  return res.status(409).json({ error: 'EFT payouts are not enabled. Eligible seller earnings are credited to the Z virtual balance automatically.' });
});

app.get('/api/admin/platform', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is not configured for this account.' });
  const [activeCommissionRate, [revenue = { commissionNAD: 0, orderCount: 0 }]] = await Promise.all([
    getPlatformCommissionRate(),
    Order.aggregate([
      { $match: { paymentStatus: 'paid' } },
      { $group: { _id: null, commissionNAD: { $sum: '$commissionNAD' }, orderCount: { $sum: 1 } } }
    ])
  ]);
  return res.json({
    commissionRatePercent: activeCommissionRate * 100,
    totalCommissionRevenueNAD: revenue.commissionNAD,
    paidOrderCount: revenue.orderCount
  });
});

app.get('/api/admin/login-wallpaper', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });
  res.set('Cache-Control', 'no-store');
  const [saved, products] = await Promise.all([
    LoginWallpaper.findOne({ key: 'login' }).lean(),
    getActivePromotedProducts()
  ]);
  const settings = serializeLoginWallpaper(saved);
  if (settings.rotatePromotions && !settings.productIds.length) {
    settings.productIds = products.map((product) => product.id);
  }
  return res.json({
    settings,
    products
  });
});

app.put('/api/admin/login-wallpaper', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });

  const normalized = normalizeLoginWallpaper(req.body);
  if (normalized.error) return res.status(400).json({ error: normalized.error });
  const activeProducts = await getActivePromotedProducts();
  const activeProductIds = new Set(activeProducts.map((product) => product.id));
  if (normalized.settings.productIds.some((id) => !activeProductIds.has(id))) {
    return res.status(400).json({ error: 'Every selected product must have an active promotion.' });
  }
  const setting = await LoginWallpaper.findOneAndUpdate(
    { key: 'login' },
    {
      $set: {
        ...normalized.settings,
        productIds: normalized.settings.productIds.map((id) => new mongoose.Types.ObjectId(id)),
        productId: normalized.settings.rotatePromotions ? null : new mongoose.Types.ObjectId(normalized.settings.productIds[0]),
        rotatePromotions: normalized.settings.rotatePromotions
      }
    },
    { returnDocument: 'after', upsert: true, runValidators: true, setDefaultsOnInsert: true }
  );
  return res.json({ settings: serializeLoginWallpaper(setting.toObject()) });
});

app.get('/api/admin/server-config', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is not configured for this account.' });
  res.set('Cache-Control', 'no-store');
  return res.json(getServerDiagnostics({
    appVersion: require('./package.json').version,
    databaseReadyState: mongoose.connection.readyState,
    platform: os.platform(),
    osRelease: os.release(),
    architecture: os.arch(),
    processUptimeSeconds: process.uptime(),
    hostUptimeSeconds: os.uptime(),
    memoryUsage: process.memoryUsage(),
    totalMemoryBytes: os.totalmem(),
    freeMemoryBytes: os.freemem(),
    nodeEnvironment: process.env.NODE_ENV
  }));
});

app.get('/api/admin/commands/tests', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is not configured for this account.' });
  res.set('Cache-Control', 'no-store');
  return res.json({ tests: listAllowedTests() });
});

app.post('/api/admin/commands/tests/run-all', async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is not configured for this account.' });
  return next();
}, commandTestRateLimit, async (req, res) => {
  try {
    const result = await runAllAllowedTests();
    res.set('Cache-Control', 'no-store');
    return res.json(result);
  } catch (error) {
    if (error.code === 'TEST_RUN_IN_PROGRESS') return res.status(409).json({ error: error.message });
    throw error;
  }
});

app.post('/api/admin/commands/tests/:testId/run', async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is not configured for this account.' });
  return next();
}, commandTestRateLimit, async (req, res) => {

  try {
    const result = await runAllowedTest(req.params.testId);
    res.set('Cache-Control', 'no-store');
    return res.json(result);
  } catch (error) {
    if (error.code === 'INVALID_TEST') return res.status(404).json({ error: error.message });
    if (error.code === 'TEST_RUN_IN_PROGRESS') return res.status(409).json({ error: error.message });
    throw error;
  }
});

app.patch('/api/admin/platform/commission', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is not configured for this account.' });
  const ratePercent = req.body?.ratePercent;
  if (!isValidCommissionRatePercent(ratePercent)) {
    return res.status(400).json({ error: 'Enter a commission percentage between 0 and 100.' });
  }
  const setting = await PlatformSetting.findOneAndUpdate(
    { key: 'commission_rate' },
    { $set: { commissionRate: ratePercent / 100 } },
    { returnDocument: 'after', upsert: true, runValidators: true, setDefaultsOnInsert: true }
  );
  return res.json({ commissionRatePercent: setting.commissionRate * 100 });
});

app.get('/api/admin/reports', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });

  const reports = await ListingReport.find({ status: 'pending' })
    .sort({ createdAt: 1 })
    .populate({ path: 'productId', populate: { path: 'shopId', select: 'name slug' } })
    .populate('reporterId', 'name dismissedListingReportCount')
    .lean();
  const productIds = [...new Set(reports.filter((report) => report.productId).map((report) => report.productId._id.toString()))];
  const counts = productIds.length
    ? await ListingReport.aggregate([
      { $match: { status: 'pending', productId: { $in: productIds.map((id) => new mongoose.Types.ObjectId(id)) } } },
      { $group: {
        _id: '$productId',
        count: { $sum: 1 },
        score: { $sum: { $ifNull: ['$credibilityPoints', 5] } }
      } }
    ])
    : [];
  const reportStatsByProduct = new Map(counts.map((entry) => [entry._id.toString(), entry]));

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
      reportCount: report.productId ? reportStatsByProduct.get(report.productId._id.toString())?.count || 0 : 0,
      reportScore: report.productId ? reportStatsByProduct.get(report.productId._id.toString())?.score || 0 : 0,
      credibilityPoints: report.credibilityPoints ?? 5,
      verifiedBuyer: Boolean(report.verifiedBuyer),
      sellerReporter: Boolean(report.sellerReporter),
      reporter: report.reporterId ? {
        name: report.reporterId.name,
        dismissedReportCount: report.reporterId.dismissedListingReportCount || 0
      } : null,
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
  ].sort((a, b) => (b.reportScore || 0) - (a.reportScore || 0) || new Date(b.createdAt) - new Date(a.createdAt));

  return res.json({ reports: queue });
});

app.get('/api/admin/seller-restrictions', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });
  await expireAutomaticSellerRestrictions();
  const shops = await Shop.find({ sellerRestrictionStatus: 'temp_hold' })
    .populate('ownerId', 'name email')
    .sort({ sellerRestrictedUntil: 1 })
    .limit(100)
    .lean();
  const shopIds = shops.map((shop) => shop._id);
  const windowStart = new Date(Date.now() - sellerRestrictionWindowMs);
  const events = shopIds.length
    ? await ListingThresholdEvent.find({ shopId: { $in: shopIds }, triggeredAt: { $gte: windowStart } })
      .sort({ triggeredAt: -1 }).populate('productId', 'title').lean()
    : [];
  const eventsByShop = new Map();
  for (const event of events) {
    const shopId = event.shopId.toString();
    const current = eventsByShop.get(shopId) || [];
    if (!current.some((item) => item.productId === event.productId?._id.toString())) {
      current.push({
        productId: event.productId?._id.toString() || '',
        productTitle: event.productId?.title || 'Listing unavailable',
        triggeredAt: event.triggeredAt
      });
    }
    eventsByShop.set(shopId, current);
  }
  return res.json({
    restrictions: shops.map((shop) => ({
      shopId: shop._id.toString(),
      shopName: shop.name,
      accountId: shop.ownerId?._id.toString() || '',
      sellerName: shop.ownerId?.name || 'Seller account unavailable',
      sellerEmail: shop.ownerId?.email || '',
      reason: shop.sellerRestrictionReason,
      restrictedUntil: shop.sellerRestrictedUntil,
      triggeredListings: eventsByShop.get(shop._id.toString()) || []
    }))
  });
});

app.patch('/api/admin/seller-restrictions/:shopId', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is required to release or permanently restrict seller access.' });
  if (!mongoose.isValidObjectId(req.params.shopId)) return res.status(404).json({ error: 'Seller restriction not found.' });
  const decision = req.body?.decision;
  if (!['release', 'ban'].includes(decision)) return res.status(400).json({ error: 'Choose whether to release or permanently restrict seller access.' });

  const shop = await Shop.findOneAndUpdate({
    _id: req.params.shopId,
    sellerRestrictionStatus: 'temp_hold'
  }, {
    $set: decision === 'release'
      ? { sellerRestrictionStatus: 'active', sellerRestrictedUntil: null, sellerRestrictionReason: '' }
      : { sellerRestrictionStatus: 'banned', sellerRestrictedUntil: null, sellerRestrictionReason: 'Permanently restricted by Super Admin after review.' }
  }, { returnDocument: 'after' }).select('_id ownerId name sellerRestrictionStatus');
  if (!shop) return res.status(404).json({ error: 'Active temporary seller restriction not found.' });
  const owner = await User.findById(shop.ownerId).select('name email').lean();
  await recordModerationAudit({
    actorId: user._id,
    actorType: 'admin',
    action: decision === 'release' ? 'seller_access_auto_released' : 'seller_access_banned',
    targetType: 'account',
    targetId: shop.ownerId.toString(),
    targetLabel: `${owner?.name || 'Seller'} (${owner?.email || 'email unavailable'})`,
    details: decision === 'release'
      ? `Super Admin released the automated seller-access hold for shop ${shop.name} (${shop._id.toString()}).`
      : `Super Admin permanently restricted seller access for shop ${shop.name} (${shop._id.toString()}) after reviewing the automated hold. Buyer access remains available.`
  });
  return res.json({
    ok: true,
    restrictionStatus: shop.sellerRestrictionStatus,
    message: decision === 'release'
      ? 'Seller access restored. Buyer access and existing order history are unchanged.'
      : 'Seller access permanently restricted. Buyer access and existing order history are unchanged.'
  });
});

app.get('/api/admin/moderation-audit', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });
  const events = await ModerationAudit.find({
    action: { $in: [
      'listing_report_dismissed', 'listing_hidden', 'listing_restored',
      'seller_access_auto_held', 'seller_access_auto_released', 'seller_access_banned'
    ] }
  }).sort({ createdAt: -1 }).limit(50).lean();
  const actorIds = events.filter((event) => event.actorId).map((event) => event.actorId);
  const actors = actorIds.length
    ? await User.find({ _id: { $in: actorIds } }).select('name email').lean()
    : [];
  const actorsById = new Map(actors.map((actor) => [actor._id.toString(), actor]));
  return res.json({ events: events.map((event) => {
    const actorId = event.actorId?.toString() || null;
    const actor = actorsById.get(actorId);
    return {
      id: event._id.toString(),
      actor: { id: actorId, name: actorId ? actor?.name || 'Deleted moderator' : 'Automated system', email: actor?.email || '', type: event.actorType },
      action: event.action,
      targetType: event.targetType,
      targetId: event.targetId,
      targetLabel: event.targetLabel,
      details: event.details,
      createdAt: event.createdAt
    };
  }) });
});

app.get('/api/admin/account-audit', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is not configured for this account.' });
  const events = await ModerationAudit.find({
    action: { $in: [
      'account_suspended', 'account_reactivated', 'seller_access_suspended', 'seller_access_reactivated',
      'seller_access_auto_held', 'seller_access_auto_released', 'seller_access_banned'
    ] }
  }).sort({ createdAt: -1 }).limit(50).lean();
  const actorIds = events.filter((event) => event.actorId).map((event) => event.actorId);
  const actors = actorIds.length
    ? await User.find({ _id: { $in: actorIds } }).select('name email').lean()
    : [];
  const actorsById = new Map(actors.map((actor) => [actor._id.toString(), actor]));
  return res.json({ events: events.map((event) => {
    const actorId = event.actorId?.toString() || null;
    const actor = actorsById.get(actorId);
    return {
      id: event._id.toString(),
      actor: { id: actorId, name: actorId ? actor?.name || 'Deleted administrator' : 'Automated system', email: actor?.email || '', type: event.actorType },
      action: event.action,
      targetId: event.targetId,
      targetLabel: event.targetLabel,
      details: event.details,
      createdAt: event.createdAt
    };
  }) });
});

app.patch('/api/admin/reports/:id', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });
  const decision = req.body?.decision;
  if (!['hide', 'restore', 'dismiss'].includes(decision)) return res.status(400).json({ error: 'Choose whether to hide, restore, or dismiss the report.' });

  if (typeof req.params.id === 'string' && req.params.id.startsWith('hidden:')) {
    const productId = req.params.id.replace(/^hidden:/, '');
    if (!mongoose.isValidObjectId(productId)) return res.status(404).json({ error: 'Hidden product not found.' });
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ error: 'Hidden product not found.' });
    if (decision === 'dismiss') return res.status(400).json({ error: 'Hidden items cannot be dismissed. Use restore to make them visible again.' });
    product.moderationStatus = decision === 'hide' ? 'hidden' : 'visible';
    product.moderationSource = decision === 'hide' ? 'moderator' : null;
    product.moderatedAt = decision === 'hide' ? new Date() : null;
    await product.save();
    await recordModerationAudit({
      actorId: user._id,
      action: decision === 'hide' ? 'listing_hidden' : 'listing_restored',
      targetType: 'listing',
      targetId: product._id.toString(),
      targetLabel: product.title,
      details: 'Manual moderator action from the hidden listings queue.'
    });
    return res.json({ ok: true, productId: product._id.toString(), moderationStatus: product.moderationStatus });
  }

  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Report not found.' });

  const report = await ListingReport.findOne({ _id: req.params.id, status: 'pending' });
  if (!report) return res.status(404).json({ error: 'Pending report not found.' });
  if (decision === 'dismiss') {
    const dismissedReport = await ListingReport.findOneAndUpdate(
      { _id: report._id, status: 'pending' },
      { $set: { status: 'dismissed', reviewedBy: user._id, reviewedAt: new Date() } },
      { returnDocument: 'after' }
    );
    if (!dismissedReport) return res.status(404).json({ error: 'Pending report not found.' });
    const reporter = await User.findByIdAndUpdate(
      dismissedReport.reporterId,
      { $inc: { dismissedListingReportCount: 1 } },
      { returnDocument: 'after' }
    ).select('dismissedListingReportCount').lean();
    const [remainingStats] = await ListingReport.aggregate([
      { $match: { productId: dismissedReport.productId, status: 'pending' } },
      { $group: {
        _id: '$productId',
        score: { $sum: { $ifNull: ['$credibilityPoints', 5] } }
      } }
    ]);
    const remainingScore = remainingStats?.score || 0;
    let restoredProduct = null;
    if (shouldRestoreReportHiddenListing('report_threshold', remainingScore)) {
      restoredProduct = await Product.findOneAndUpdate({
        _id: dismissedReport.productId,
        moderationStatus: 'hidden',
        moderationSource: 'report_threshold'
      }, {
        $set: { moderationStatus: 'visible', moderationSource: null, moderatedAt: null }
      }, { returnDocument: 'after' }).select('title').lean();
    }
    await recordModerationAudit({
      actorId: user._id,
      action: 'listing_report_dismissed',
      targetType: 'listing_report',
      targetId: dismissedReport._id.toString(),
      targetLabel: report.productId.toString(),
      details: `Dismissed report for ${report.reason}; reporter ${dismissedReport.reporterId.toString()}.`
    });
    if (restoredProduct) {
      await recordModerationAudit({
        actorId: user._id,
        action: 'listing_restored',
        targetType: 'listing',
        targetId: dismissedReport.productId.toString(),
        targetLabel: restoredProduct.title,
        details: 'Automatically restored after a dismissed report reduced the pending score below the hide threshold.'
      });
    }
    return res.json({
      ok: true,
      productId: dismissedReport.productId.toString(),
      dismissed: true,
      reporterDismissedCount: reporter?.dismissedListingReportCount || 0,
      reporterBlocked: isListingReportBlocked(reporter?.dismissedListingReportCount || 0),
      remainingReportScore: remainingScore
    });
  }

  const moderationStatus = decision === 'hide' ? 'hidden' : 'visible';
  const product = await Product.findByIdAndUpdate(report.productId, {
    $set: {
      moderationStatus,
      moderationSource: decision === 'hide' ? 'moderator' : null,
      moderatedAt: decision === 'hide' ? new Date() : null
    }
  }, { returnDocument: 'after' }).select('title').lean();
  await ListingReport.updateMany({ productId: report.productId, status: 'pending' }, {
    $set: { status: 'actioned', reviewedBy: user._id, reviewedAt: new Date() }
  });
  await recordModerationAudit({
    actorId: user._id,
    action: decision === 'hide' ? 'listing_hidden' : 'listing_restored',
    targetType: 'listing',
    targetId: report.productId.toString(),
    targetLabel: product?.title || '',
    details: `Moderator ${decision} action applied from report ${report._id.toString()}.`
  });
  return res.json({ ok: true, productId: report.productId.toString(), moderationStatus });
});

app.get('/api/admin/review-queue', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });
  const [shops, products] = await Promise.all([
    Shop.find({ approvalStatus: 'pending' })
      .select('name slug description town approvalNote createdAt')
      .populate('ownerId', 'name')
      .sort({ createdAt: 1 })
      .limit(100)
      .lean(),
    Product.find({ reviewStatus: 'pending', status: 'active' })
      .select('title description category priceNAD imageUrl createdAt shopId reviewReasons')
      .populate('shopId', 'name slug')
      .sort({ createdAt: 1 })
      .limit(100)
      .lean()
  ]);
  return res.json({
    shops: shops.map((shop) => ({
      id: shop._id.toString(),
      name: shop.name,
      slug: shop.slug,
      description: shop.description,
      town: shop.town,
      approvalNote: shop.approvalNote,
      submittedAt: shop.createdAt,
      ownerName: shop.ownerId?.name || 'Unknown account'
    })),
    products: products.map((product) => ({
      id: product._id.toString(),
      title: product.title,
      description: product.description,
      category: product.category,
      priceNAD: product.priceNAD,
      imageUrl: product.imageUrl,
      submittedAt: product.createdAt,
      shopName: product.shopId?.name || 'Unknown shop',
      reviewReasons: product.reviewReasons || []
    }))
  });
});

app.patch('/api/admin/shops/:id/approval', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Pending shop not found.' });
  const decision = req.body?.decision;
  const approvalNote = typeof req.body?.approvalNote === 'string' ? req.body.approvalNote.trim() : '';
  if (!['approve', 'reject'].includes(decision) || approvalNote.length > 500 || (decision === 'reject' && approvalNote.length < 5)) {
    return res.status(400).json({ error: 'Choose approve or reject; rejected shops require a short explanation.' });
  }
  const shop = await Shop.findOneAndUpdate(
    { _id: req.params.id, approvalStatus: 'pending' },
    { $set: { approvalStatus: decision === 'approve' ? 'approved' : 'rejected', approvalNote } },
    { returnDocument: 'after', runValidators: true }
  );
  if (!shop) return res.status(404).json({ error: 'Pending shop not found.' });
  return res.json({ ok: true, approvalStatus: shop.approvalStatus, approvalNote: shop.approvalNote });
});

app.patch('/api/admin/products/:id/review', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Pending listing not found.' });
  const decision = req.body?.decision;
  if (!['approve', 'reject'].includes(decision)) return res.status(400).json({ error: 'Choose approve or reject.' });
  if (decision === 'approve') {
    const product = await Product.findOne({ _id: req.params.id, reviewStatus: 'pending' })
      .select('title description category imageUrl imageUrls priceNAD stock').lean();
    if (!product) return res.status(404).json({ error: 'Pending listing not found.' });
    const dataIssues = getProductBasicDataIssues(product);
    if (dataIssues.length) return res.status(409).json({ error: `Complete the basic product checks before approval: ${dataIssues.join(' ')}` });
  }
  const product = await Product.findOneAndUpdate(
    { _id: req.params.id, reviewStatus: 'pending' },
    { $set: { reviewStatus: decision === 'approve' ? 'approved' : 'rejected' } },
    { returnDocument: 'after', runValidators: true }
  );
  if (!product) return res.status(404).json({ error: 'Pending listing not found.' });
  return res.json({ ok: true, reviewStatus: product.reviewStatus });
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

app.get('/api/admin/users', async (req, res) => {
  const moderator = await getSessionUser(req);
  if (!moderator || !isAdminUser(moderator)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });

  const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';
  const status = typeof req.query.status === 'string' ? req.query.status : 'all';
  const accountType = typeof req.query.accountType === 'string' ? req.query.accountType : 'all';
  const page = req.query.page === undefined ? 1 : Number(req.query.page);
  if (search.length > 100 || !['all', 'active', 'suspended'].includes(status) || !['all', 'buyer', 'seller', 'moderator'].includes(accountType) || !Number.isInteger(page) || page < 1 || page > 10000) {
    return res.status(400).json({ error: 'Check the account search, type, status, and page.' });
  }

  const filters = [];
  let sellerIds = null;
  if (accountType === 'moderator') {
    filters.push({ role: 'moderator' });
  } else if (accountType === 'buyer' || accountType === 'seller') {
    sellerIds = await Shop.distinct('ownerId');
    filters.push({ _id: accountType === 'seller' ? { $in: sellerIds } : { $nin: sellerIds } });
  }
  if (search) {
    const expression = new RegExp(escapeRegex(search), 'i');
    filters.push({ $or: [{ name: expression }, { email: expression }] });
  }
  if (status === 'suspended') filters.push({ isSuspended: true });
  if (status === 'active') filters.push({ $or: [{ isSuspended: false }, { isSuspended: { $exists: false } }] });
  const filter = filters.length > 1 ? { $and: filters } : filters[0] || {};
  const pageSize = 25;
  const [total, users] = await Promise.all([
    User.countDocuments(filter),
    User.find(filter)
      .select('name email emailVerified phone town createdAt isSuspended role')
      .sort({ createdAt: -1, _id: -1 })
      .skip((page - 1) * pageSize)
      .limit(pageSize)
      .lean()
  ]);
  const sellerShops = users.length
    ? await Shop.find({ ownerId: { $in: users.map((account) => account._id) } })
      .select('ownerId sellerSuspended sellerRestrictionStatus sellerRestrictedUntil').lean()
    : [];
  const sellerShopByOwner = new Map(sellerShops.map((shop) => [shop.ownerId.toString(), shop]));
  if (sellerIds === null) {
    sellerIds = await Shop.distinct('ownerId', { ownerId: { $in: users.map((account) => account._id) } });
  }
  const sellerIdSet = new Set(sellerIds.map((id) => id.toString()));
  return res.json({
    users: users.map((account) => ({
      id: account._id.toString(),
      name: account.name,
      email: account.email,
      emailVerified: Boolean(account.emailVerified),
      phone: account.phone || '',
      town: account.town || '',
      createdAt: account.createdAt,
      isSuspended: Boolean(account.isSuspended),
      sellerSuspended: isSellerInventoryRestricted(sellerShopByOwner.get(account._id.toString())),
      sellerRestrictionStatus: sellerShopByOwner.get(account._id.toString())?.sellerRestrictionStatus || 'active',
      sellerRestrictedUntil: sellerShopByOwner.get(account._id.toString())?.sellerRestrictedUntil || null,
      accountType: sellerIdSet.has(account._id.toString()) ? 'seller' : 'buyer',
      role: getPublicRole(account),
      isModerator: isModeratorUser(account),
      isSuperAdmin: isAdminUser(account),
      isOwnerIdentity: isConfiguredAdminIdentity(account)
    })),
    page,
    pageSize,
    total,
    pages: Math.ceil(total / pageSize)
  });
});

app.get('/api/admin/users/:id/transactions', async (req, res) => {
  const admin = await getSessionUser(req);
  if (!admin || !isAdminUser(admin)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Account not found.' });

  const type = typeof req.query.type === 'string' ? req.query.type : 'buyer-orders';
  const page = req.query.page === undefined ? 1 : Number(req.query.page);
  const pageSize = req.query.pageSize === undefined ? 25 : Number(req.query.pageSize);
  const supportedTypes = [
    'buyer-orders', 'seller-orders', 'wallet', 'payouts', 'promotions',
    'cart', 'wishlist',
    'listings', 'reviews-written', 'listing-reports', 'reports-on-listings',
    'listing-moderation', 'listing-engagement', 'support-requests', 'login-activity',
    'appeals', 'notifications', 'seller-notifications', 'developer-applications',
    'developer-usage', 'statements', 'account-audit', 'submitted-report-moderation',
    'listing-review-actions', 'reviews-received', 'threshold-events',
    'support-notifications', 'sessions', 'password-resets', 'email-verifications',
    'appeal-access', 'referrals'
  ];
  if (!supportedTypes.includes(type)) return res.status(400).json({ error: 'Choose a supported transaction type.' });
  if (!Number.isSafeInteger(page) || page < 1 || !Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 100 || !Number.isSafeInteger((page - 1) * pageSize)) {
    return res.status(400).json({ error: 'Page must be a positive integer and page size must be between 1 and 100.' });
  }

  const account = await User.findById(req.params.id).select('name email').lean();
  if (!account) return res.status(404).json({ error: 'Account not found.' });
  const skip = (page - 1) * pageSize;
  let records;
  let total;

  if (type === 'cart' || type === 'wishlist') {
    const field = type === 'cart' ? 'cartItems' : 'wishlistProductIds';
    const [result] = await User.aggregate([
      { $match: { _id: account._id } },
      { $project: { items: { $ifNull: [`$${field}`, []] } } },
      { $facet: {
        records: [
          { $unwind: { path: '$items', includeArrayIndex: 'index' } },
          { $sort: { index: 1 } },
          { $skip: skip },
          { $limit: pageSize },
          { $project: {
            _id: 0,
            productId: type === 'cart' ? '$items.productId' : '$items',
            quantity: type === 'cart' ? '$items.quantity' : { $literal: 1 }
          } }
        ],
        total: [{ $project: { count: { $size: '$items' } } }, { $group: { _id: null, count: { $sum: '$count' } } }]
      } }
    ]);
    records = result?.records || [];
    total = result?.total?.[0]?.count || 0;
  } else if (type === 'buyer-orders') {
    [records, total] = await Promise.all([
      Order.find({ buyerId: account._id }).sort({ createdAt: -1, _id: -1 }).skip(skip).limit(pageSize)
        .select('buyerId orderNumber sellerOrders items productsSubtotalNAD shippingNAD commissionNAD commissionRate totalNAD paymentStatus paymentMethod paymentMode paymentReference walletUsedNAD cardDueNAD deliveryTown reservationExpiresAt reservationsReleasedAt paidAt createdAt updatedAt').lean(),
      Order.countDocuments({ buyerId: account._id })
    ]);
  } else if (type === 'seller-orders') {
    [records, total] = await Promise.all([
      Order.aggregate([
        { $unwind: '$sellerOrders' },
        { $match: { 'sellerOrders.sellerId': account._id } },
        { $sort: { createdAt: -1, _id: -1, 'sellerOrders._id': -1 } },
        { $skip: skip },
        { $limit: pageSize },
        { $project: {
          _id: 0,
          orderId: { $toString: '$_id' },
          sellerOrderId: { $toString: '$sellerOrders._id' },
          orderNumber: 1,
          totalNAD: 1,
          paymentStatus: 1,
          paymentMethod: 1,
          paymentMode: 1,
          paymentReference: 1,
          walletUsedNAD: 1,
          cardDueNAD: 1,
          createdAt: 1,
          updatedAt: 1,
          paidAt: 1,
          shopId: '$sellerOrders.shopId',
          shopName: '$sellerOrders.shopName',
          sellerTown: '$sellerOrders.sellerTown',
          deliveryTown: '$sellerOrders.deliveryTown',
          shippingZone: '$sellerOrders.shippingZone',
          items: '$sellerOrders.items',
          productsSubtotalNAD: '$sellerOrders.productsSubtotalNAD',
          shippingNAD: '$sellerOrders.shippingNAD',
          commissionNAD: '$sellerOrders.commissionNAD',
          commissionRate: '$sellerOrders.commissionRate',
          payoutNAD: '$sellerOrders.payoutNAD',
          approvalStatus: '$sellerOrders.approvalStatus',
          fulfillmentStatus: '$sellerOrders.fulfillmentStatus',
          payoutStatus: '$sellerOrders.payoutStatus',
          trackingReference: '$sellerOrders.trackingReference',
          deliveredAt: '$sellerOrders.deliveredAt',
          payoutEligibleAt: '$sellerOrders.payoutEligibleAt',
          walletCreditedAt: '$sellerOrders.walletCreditedAt',
          payoutReference: '$sellerOrders.payoutReference',
          payoutMarkedAt: '$sellerOrders.payoutMarkedAt'
        } }
      ]),
      Order.countDocuments({ 'sellerOrders.sellerId': account._id })
    ]);
  } else if (type === 'wallet') {
    [records, total] = await Promise.all([
      WalletTransaction.find({ userId: account._id }).sort({ createdAt: -1, _id: -1 }).skip(skip).limit(pageSize)
        .select('type amountNAD balanceAfterNAD orderNumber description reference createdAt updatedAt').lean(),
      WalletTransaction.countDocuments({ userId: account._id })
    ]);
  } else if (type === 'payouts') {
    [records, total] = await Promise.all([
      SimulatedPayoutRequest.find({ userId: account._id }).sort({ createdAt: -1, _id: -1 }).skip(skip).limit(pageSize)
        .select('shopId amountNAD status mode destination createdAt updatedAt').lean(),
      SimulatedPayoutRequest.countDocuments({ userId: account._id })
    ]);
  } else if (type === 'promotions') {
    [records, total] = await Promise.all([
      PromotionCampaign.find({ sellerId: account._id }).sort({ createdAt: -1, _id: -1 }).skip(skip).limit(pageSize)
        .populate('productId', 'title').select('productId shopId amountNAD durationDays status paymentMethod walletUsedNAD cardDueNAD paymentExpiresAt paidAt startsAt expiresAt createdAt updatedAt').lean(),
      PromotionCampaign.countDocuments({ sellerId: account._id })
    ]);
  } else {
    const shop = ['listings', 'reports-on-listings', 'listing-moderation', 'listing-engagement', 'reviews-received', 'threshold-events'].includes(type)
      ? await Shop.findOne({ ownerId: account._id }).select('_id').lean()
      : null;
    const simpleQueries = {
      listings: shop ? [Product, { shopId: shop._id }, 'title description priceNAD stock isAvailable category town imageUrl imageUrls status reviewStatus reviewReasons moderationStatus moderationSource moderatedAt createdAt updatedAt', null, { createdAt: -1, _id: -1 }] : null,
      'reviews-written': [ShopReview, { userId: account._id }, 'shopId rating comment createdAt updatedAt', { path: 'shopId', select: 'name' }, { createdAt: -1, _id: -1 }],
      'listing-reports': [ListingReport, { reporterId: account._id }, 'productId reviewedBy reason details status credibilityPoints verifiedBuyer sellerReporter createdAt updatedAt reviewedAt', [{ path: 'productId', select: 'title' }, { path: 'reviewedBy', select: 'name' }], { createdAt: -1, _id: -1 }],
      'support-requests': [SupportRequest, { buyerId: account._id }, 'orderId orderNumber category topic message status adminResponse createdAt updatedAt', null, { createdAt: -1, _id: -1 }],
      'login-activity': [LoginActivity, { userId: account._id }, 'device client_ip country_code city isp_provider readAt expiresAt createdAt updatedAt', null, { createdAt: -1, _id: -1 }],
      appeals: [SuspensionAppeal, { accountEmail: account.email }, 'reason referenceId status createdAt updatedAt', null, { createdAt: -1, _id: -1 }],
      notifications: [AccountNotification, { userId: account._id }, 'createdBy title message destination accountReadAt sellerReadAt createdAt updatedAt', { path: 'createdBy', select: 'name' }, { createdAt: -1, _id: -1 }],
      'seller-notifications': [SellerNotification, { userId: account._id }, 'type promotionId title message readAt createdAt updatedAt', { path: 'promotionId', select: 'status startsAt expiresAt' }, { createdAt: -1, _id: -1 }],
      'developer-applications': [DeveloperApplication, { ownerId: account._id }, 'appId name tokenLast4 revokedAt lastUsedAt createdAt updatedAt', null, { createdAt: -1, _id: -1 }],
      statements: [SellerStatement, { userId: account._id }, 'statementId snapshot createdAt updatedAt', null, { createdAt: -1, _id: -1 }],
      'listing-review-actions': [ListingReport, { reviewedBy: account._id }, 'productId reporterId reason status reviewedAt createdAt', [{ path: 'productId', select: 'title' }, { path: 'reporterId', select: 'name' }], { reviewedAt: -1, _id: -1 }],
      'reviews-received': shop ? [ShopReview, { shopId: shop._id }, 'userId rating comment createdAt updatedAt', { path: 'userId', select: 'name email' }, { createdAt: -1, _id: -1 }] : null,
      'threshold-events': shop ? [ListingThresholdEvent, { shopId: shop._id }, 'shopId productId triggeredAt', null, { triggeredAt: -1, _id: -1 }] : null,
      'support-notifications': [SupportNotification, { userId: account._id }, 'supportRequestId readAt createdAt updatedAt', { path: 'supportRequestId', select: 'topic status createdAt' }, { createdAt: -1, _id: -1 }],
      sessions: [Session, { userId: account._id }, 'createdAt updatedAt expiresAt', null, { createdAt: -1, _id: -1 }],
      'password-resets': [PasswordReset, { userId: account._id }, 'createdAt expiresAt', null, { createdAt: -1, _id: -1 }],
      'email-verifications': [EmailVerification, { userId: account._id }, 'createdAt expiresAt', null, { createdAt: -1, _id: -1 }],
      'appeal-access': [SuspensionAppealAccess, { accountEmail: account.email }, 'createdAt expiresAt', null, { createdAt: -1, _id: -1 }],
      referrals: [User, { referredBy: account._id }, 'name email createdAt', null, { createdAt: -1, _id: -1 }]
    };

    if (simpleQueries[type]) {
      const [Model, filter, fields, populate, sort] = simpleQueries[type];
      [records, total] = await Promise.all([
        (() => {
          let query = Model.find(filter).sort(sort).skip(skip).limit(pageSize);
          if (populate) query = Array.isArray(populate)
            ? populate.reduce((current, option) => current.populate(option), query)
            : query.populate(populate);
          return query.select(fields).lean();
        })(),
        Model.countDocuments(filter)
      ]);
    } else if (Object.prototype.hasOwnProperty.call(simpleQueries, type)) {
      records = [];
      total = 0;
    } else if (type === 'account-audit') {
      const filter = { $or: [{ targetType: 'account', targetId: account._id.toString() }, { actorId: account._id }] };
      [records, total] = await Promise.all([
        ModerationAudit.find(filter).sort({ createdAt: -1, _id: -1 }).skip(skip).limit(pageSize)
          .populate('actorId', 'name').select('action details targetType targetId targetLabel actorId actorType createdAt').lean(),
        ModerationAudit.countDocuments(filter)
      ]);
    } else if (['reports-on-listings', 'listing-moderation', 'listing-engagement'].includes(type)) {
      if (!shop) {
        records = [];
        total = 0;
      } else if (type === 'listing-engagement') {
        const [result] = await PromotionEngagement.aggregate([
          { $match: { shopId: shop._id } },
          { $group: { _id: { campaignId: '$campaignId', date: '$date', eventType: '$eventType', placement: '$placement' }, count: { $sum: 1 } } },
          { $sort: { '_id.date': -1, '_id.campaignId': 1, '_id.eventType': 1, '_id.placement': 1 } },
          { $facet: {
            records: [{ $skip: skip }, { $limit: pageSize }],
            total: [{ $count: 'count' }]
          } }
        ]);
        records = (result?.records || []).map((entry) => ({
          campaignId: entry._id.campaignId,
          date: entry._id.date,
          eventType: entry._id.eventType,
          placement: entry._id.placement,
          count: entry.count
        }));
        total = result?.total?.[0]?.count || 0;
      } else {
        const listingIds = await Product.distinct('_id', { shopId: shop._id });
        const filter = type === 'reports-on-listings'
          ? { productId: { $in: listingIds } }
          : { targetType: 'listing', targetId: { $in: listingIds.map((id) => id.toString()) } };
        const Model = type === 'reports-on-listings' ? ListingReport : ModerationAudit;
        let query = Model.find(filter).sort({ createdAt: -1, _id: -1 }).skip(skip).limit(pageSize);
        if (type === 'reports-on-listings') {
          query = query.populate('productId', 'title').populate('reporterId', 'name').populate('reviewedBy', 'name')
            .select('productId reporterId reviewedBy reason details status credibilityPoints verifiedBuyer sellerReporter createdAt reviewedAt');
        } else {
          query = query.populate('actorId', 'name').select('action details targetLabel actorId actorType createdAt');
        }
        [records, total] = await Promise.all([query.lean(), Model.countDocuments(filter)]);
      }
    } else if (type === 'submitted-report-moderation') {
      const reportIds = await ListingReport.distinct('_id', { reporterId: account._id });
      const filter = { targetType: 'listing_report', targetId: { $in: reportIds.map((id) => id.toString()) } };
      [records, total] = await Promise.all([
        ModerationAudit.find(filter).sort({ createdAt: -1, _id: -1 }).skip(skip).limit(pageSize)
          .populate('actorId', 'name').select('action details targetId targetLabel actorId actorType createdAt').lean(),
        ModerationAudit.countDocuments(filter)
      ]);
    } else if (type === 'developer-usage') {
      const appIds = await DeveloperApplication.distinct('appId', { ownerId: account._id });
      const filter = { appId: { $in: appIds } };
      [records, total] = await Promise.all([
        DeveloperApiUsage.find(filter).sort({ day: -1, endpoint: 1, appId: 1 }).skip(skip).limit(pageSize)
          .select('appId day endpoint requests successes verified mismatched clientErrors serverErrors totalDurationMs expiresAt').lean(),
        DeveloperApiUsage.countDocuments(filter)
      ]);
    }
  }

  return res.json({
    account: { id: account._id.toString(), name: account.name, email: account.email },
    type,
    records,
    page,
    pageSize,
    total,
    pages: Math.ceil(total / pageSize)
  });
});

app.get('/api/admin/users/:id/details', async (req, res) => {
  const admin = await getSessionUser(req);
  if (!admin || !isAdminUser(admin)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Account not found.' });

  const account = await User.findById(req.params.id)
    .select('name email phone town role emailVerified isSuspended walletBalanceNAD payoutBankAccount dismissedListingReportCount referralCode referredBy createdAt updatedAt')
    .lean();
  if (!account) return res.status(404).json({ error: 'Account not found.' });

  const [accountCollections] = await User.aggregate([
    { $match: { _id: account._id } },
    { $project: {
      cartItems: { $slice: [{ $ifNull: ['$cartItems', []] }, 10] },
      cartItemCount: { $size: { $ifNull: ['$cartItems', []] } },
      wishlistProductIds: { $slice: [{ $ifNull: ['$wishlistProductIds', []] }, 10] },
      wishlistCount: { $size: { $ifNull: ['$wishlistProductIds', []] } }
    } }
  ]);
  const cartItemsPreview = accountCollections?.cartItems || [];
  const wishlistPreview = accountCollections?.wishlistProductIds || [];
  const sellerShop = await Shop.findOne({ ownerId: account._id }).select('-kycDocumentId -nameKey -__v').lean();
  const [
    listings, listingCount, buyerOrderCount, paidBuyerTotals, sellerOrderCount,
    sellerPayoutTotals, walletTotals, walletTransactionCount, payoutRequestCount, promotionCount, reviews, reviewCount, cartProducts,
    submittedReports, submittedReportCount, supportRequests, supportRequestCount, loginActivities,
    appeals, notifications, sellerNotifications, developerApplications, statements, sessions,
    passwordResets, emailVerifications, supportNotifications, accountAuditEvents, listingReviewActions,
    receivedReviews, thresholdEvents, appealAccessRecords
  ] = await Promise.all([
    sellerShop
      ? Product.find({ shopId: sellerShop._id }).sort({ createdAt: -1 }).limit(10).lean()
      : Promise.resolve([]),
    sellerShop ? Product.countDocuments({ shopId: sellerShop._id }) : Promise.resolve(0),
    Order.countDocuments({ buyerId: account._id }),
    Order.aggregate([
      { $match: { buyerId: account._id, paymentStatus: 'paid' } },
      { $group: { _id: null, totalNAD: { $sum: '$totalNAD' }, count: { $sum: 1 } } }
    ]),
    Order.countDocuments({ 'sellerOrders.sellerId': account._id }),
    Order.aggregate([
      { $match: { paymentStatus: 'paid' } },
      { $unwind: '$sellerOrders' },
      { $match: { 'sellerOrders.sellerId': account._id } },
      { $group: {
        _id: null,
        totalPayoutNAD: { $sum: '$sellerOrders.payoutNAD' },
        creditedToWalletNAD: {
          $sum: { $cond: [{ $ne: [{ $ifNull: ['$sellerOrders.walletCreditedAt', null] }, null] }, '$sellerOrders.payoutNAD', 0] }
        },
        awaitingWalletCreditNAD: {
          $sum: { $cond: [{ $eq: [{ $ifNull: ['$sellerOrders.walletCreditedAt', null] }, null] }, '$sellerOrders.payoutNAD', 0] }
        },
        orderCount: { $sum: 1 }
      } }
    ]),
    WalletTransaction.aggregate([
      { $match: { userId: account._id } },
      { $group: { _id: '$type', amountNAD: { $sum: '$amountNAD' }, count: { $sum: 1 } } }
    ]),
    WalletTransaction.countDocuments({ userId: account._id }),
    SimulatedPayoutRequest.countDocuments({ userId: account._id }),
    PromotionCampaign.countDocuments({ sellerId: account._id }),
    ShopReview.find({ userId: account._id }).sort({ createdAt: -1 }).limit(10)
      .populate('shopId', 'name').select('shopId rating comment createdAt updatedAt').lean(),
    ShopReview.countDocuments({ userId: account._id }),
    Product.find({
      _id: { $in: [...cartItemsPreview.map((item) => item.productId), ...wishlistPreview] }
    }).select('title priceNAD status').lean(),
    ListingReport.find({ reporterId: account._id }).sort({ createdAt: -1 }).limit(10)
      .populate('productId', 'title').populate('reviewedBy', 'name')
      .select('productId reviewedBy reason details status credibilityPoints verifiedBuyer sellerReporter createdAt updatedAt reviewedAt').lean(),
    ListingReport.countDocuments({ reporterId: account._id }),
    SupportRequest.find({ buyerId: account._id }).sort({ createdAt: -1 }).limit(10)
      .select('orderNumber category topic message status adminResponse createdAt updatedAt').lean(),
    SupportRequest.countDocuments({ buyerId: account._id }),
    LoginActivity.find({ userId: account._id }).sort({ createdAt: -1 }).limit(10)
      .select('device client_ip country_code city isp_provider readAt expiresAt createdAt updatedAt').lean(),
    SuspensionAppeal.find({ accountEmail: account.email }).sort({ createdAt: -1 }).limit(10)
      .select('reason referenceId status createdAt updatedAt').lean(),
    AccountNotification.find({ userId: account._id }).sort({ createdAt: -1 }).limit(10)
      .populate('createdBy', 'name').select('createdBy title message destination accountReadAt sellerReadAt createdAt updatedAt').lean(),
    SellerNotification.find({ userId: account._id }).sort({ createdAt: -1 }).limit(10)
      .populate('promotionId', 'status startsAt expiresAt').select('type promotionId title message readAt createdAt updatedAt').lean(),
    DeveloperApplication.find({ ownerId: account._id }).sort({ createdAt: -1 }).limit(10)
      .select('appId name tokenLast4 revokedAt lastUsedAt createdAt updatedAt').lean(),
    SellerStatement.find({ userId: account._id }).sort({ createdAt: -1 }).limit(10)
      .select('statementId snapshot createdAt updatedAt').lean(),
    Session.find({ userId: account._id }).sort({ createdAt: -1 }).limit(10)
      .select('createdAt updatedAt expiresAt').lean(),
    PasswordReset.find({ userId: account._id }).sort({ createdAt: -1 }).limit(10)
      .select('createdAt expiresAt').lean(),
    EmailVerification.find({ userId: account._id }).sort({ createdAt: -1 }).limit(10)
      .select('createdAt expiresAt').lean(),
    SupportNotification.find({ userId: account._id }).sort({ createdAt: -1 }).limit(10)
      .populate('supportRequestId', 'topic status createdAt').select('supportRequestId readAt createdAt updatedAt').lean(),
    ModerationAudit.find({
      $or: [
        { targetType: 'account', targetId: account._id.toString() },
        { actorId: account._id }
      ]
    }).sort({ createdAt: -1 }).limit(10).populate('actorId', 'name').lean(),
    ListingReport.find({ reviewedBy: account._id }).sort({ reviewedAt: -1 }).limit(10)
      .populate('productId', 'title').populate('reporterId', 'name')
      .select('productId reporterId reason status reviewedAt createdAt').lean(),
    sellerShop
      ? ShopReview.find({ shopId: sellerShop._id }).sort({ createdAt: -1 }).limit(10)
        .populate('userId', 'name email').lean()
      : Promise.resolve([]),
    sellerShop
      ? ListingThresholdEvent.find({ shopId: sellerShop._id }).sort({ triggeredAt: -1 }).limit(10).lean()
      : Promise.resolve([]),
    SuspensionAppealAccess.find({ accountEmail: account.email }).sort({ createdAt: -1 }).limit(10)
      .select('createdAt expiresAt').lean()
  ]);
  const listingIds = sellerShop ? await Product.distinct('_id', { shopId: sellerShop._id }) : [];
  const submittedReportIds = await ListingReport.distinct('_id', { reporterId: account._id });
  const [reportsOnListings, listingModerationEvents, listingEngagement, referredUsers, submittedReportModerationEvents] = await Promise.all([
    listingIds.length
      ? ListingReport.find({ productId: { $in: listingIds } }).sort({ createdAt: -1 }).limit(10)
        .populate('productId', 'title').populate('reporterId', 'name').populate('reviewedBy', 'name')
        .select('productId reporterId reviewedBy reason details status credibilityPoints verifiedBuyer sellerReporter createdAt reviewedAt').lean()
      : Promise.resolve([]),
    listingIds.length
      ? ModerationAudit.find({ targetType: 'listing', targetId: { $in: listingIds.map((id) => id.toString()) } })
        .sort({ createdAt: -1 }).limit(10).populate('actorId', 'name').lean()
      : Promise.resolve([]),
    sellerShop
      ? PromotionEngagement.aggregate([
        { $match: { shopId: sellerShop._id } },
        { $group: { _id: { campaignId: '$campaignId', date: '$date', eventType: '$eventType', placement: '$placement' }, count: { $sum: 1 } } },
        { $sort: { '_id.date': -1 } },
        { $limit: 10 }
      ])
      : Promise.resolve([]),
    User.find({ referredBy: account._id }).sort({ createdAt: -1 }).limit(10)
      .select('name email createdAt').lean(),
    submittedReportIds.length
      ? ModerationAudit.find({
        targetType: 'listing_report',
        targetId: { $in: submittedReportIds.map((id) => id.toString()) }
      }).sort({ createdAt: -1 }).limit(10).populate('actorId', 'name').lean()
      : Promise.resolve([])
  ]);
  const listingReportCount = listingIds.length
    ? await ListingReport.countDocuments({ productId: { $in: listingIds } })
    : 0;
  const listingModerationEventCount = listingIds.length
    ? await ModerationAudit.countDocuments({ targetType: 'listing', targetId: { $in: listingIds.map((id) => id.toString()) } })
    : 0;
  const developerUsage = developerApplications.length
    ? await DeveloperApiUsage.aggregate([
      { $match: { appId: { $in: developerApplications.map((application) => application.appId) } } },
      { $group: {
        _id: '$appId',
        requests: { $sum: '$requests' },
        verified: { $sum: '$verified' },
        mismatched: { $sum: '$mismatched' },
        lastActivity: { $max: '$day' }
      } }
    ])
    : [];
  const allDeveloperAppIds = await DeveloperApplication.distinct('appId', { ownerId: account._id });
  const developerUsageRecords = allDeveloperAppIds.length
    ? await DeveloperApiUsage.find({ appId: { $in: allDeveloperAppIds } })
      .sort({ day: -1, endpoint: 1 }).limit(10)
      .select('appId day endpoint requests successes verified mismatched clientErrors serverErrors totalDurationMs expiresAt').lean()
    : [];
  const accountAuditFilter = {
    $or: [
      { targetType: 'account', targetId: account._id.toString() },
      { actorId: account._id }
    ]
  };
  const submittedReportAuditFilter = {
    targetType: 'listing_report',
    targetId: { $in: submittedReportIds.map((id) => id.toString()) }
  };
  const [
    sellerNotificationCount, statementCount, sessionCount, passwordResetCount,
    emailVerificationCount, supportNotificationCount, accountAuditCount,
    listingReviewActionCount, receivedReviewCount, thresholdEventCount,
    appealAccessCount, developerUsageCount, submittedReportModerationCount,
    listingEngagementCount, referralCount, appealCount, notificationCount,
    developerApplicationCount, loginActivityCount
  ] = await Promise.all([
    SellerNotification.countDocuments({ userId: account._id }),
    SellerStatement.countDocuments({ userId: account._id }),
    Session.countDocuments({ userId: account._id }),
    PasswordReset.countDocuments({ userId: account._id }),
    EmailVerification.countDocuments({ userId: account._id }),
    SupportNotification.countDocuments({ userId: account._id }),
    ModerationAudit.countDocuments(accountAuditFilter),
    ListingReport.countDocuments({ reviewedBy: account._id }),
    sellerShop ? ShopReview.countDocuments({ shopId: sellerShop._id }) : Promise.resolve(0),
    sellerShop ? ListingThresholdEvent.countDocuments({ shopId: sellerShop._id }) : Promise.resolve(0),
    SuspensionAppealAccess.countDocuments({ accountEmail: account.email }),
    allDeveloperAppIds.length ? DeveloperApiUsage.countDocuments({ appId: { $in: allDeveloperAppIds } }) : Promise.resolve(0),
    submittedReportIds.length ? ModerationAudit.countDocuments(submittedReportAuditFilter) : Promise.resolve(0),
    sellerShop
      ? PromotionEngagement.aggregate([
        { $match: { shopId: sellerShop._id } },
        { $group: { _id: { campaignId: '$campaignId', date: '$date', eventType: '$eventType', placement: '$placement' } } },
        { $count: 'count' }
      ]).then((result) => result[0]?.count || 0)
      : Promise.resolve(0),
    User.countDocuments({ referredBy: account._id }),
    SuspensionAppeal.countDocuments({ accountEmail: account.email }),
    AccountNotification.countDocuments({ userId: account._id }),
    DeveloperApplication.countDocuments({ ownerId: account._id }),
    LoginActivity.countDocuments({ userId: account._id })
  ]);
  const referralSource = account.referredBy
    ? await User.findById(account.referredBy).select('name email createdAt').lean()
    : null;
  const usageByApplication = new Map(developerUsage.map((usage) => [usage._id, usage]));
  const walletTotalsByType = Object.fromEntries(walletTotals.map((entry) => [entry._id, {
    amountNAD: roundNAD(entry.amountNAD),
    count: entry.count
  }]));
  const sellerPayoutSummary = sellerPayoutTotals[0] || {
    totalPayoutNAD: 0,
    creditedToWalletNAD: 0,
    awaitingWalletCreditNAD: 0,
    orderCount: 0
  };
  return res.json({
    details: {
      profile: {
        id: account._id.toString(),
        name: account.name,
        email: account.email,
        phone: account.phone || '',
        town: account.town || '',
        payoutBankAccount: account.payoutBankAccount ? {
          bankName: account.payoutBankAccount.bankName || '',
          accountName: account.payoutBankAccount.accountName || '',
          accountLast4: account.payoutBankAccount.accountLast4 || ''
        } : null,
        dismissedListingReportCount: account.dismissedListingReportCount || 0,
        accountType: sellerShop ? 'Seller' : 'Buyer',
        role: getPublicRole(account),
        emailVerified: Boolean(account.emailVerified),
        isSuspended: Boolean(account.isSuspended),
        isModerator: isModeratorUser(account),
        isSuperAdmin: isAdminUser(account),
        isConfiguredAdminIdentity: isConfiguredAdminIdentity(account),
        walletBalanceNAD: roundNAD(account.walletBalanceNAD || 0),
        referralCode: account.referralCode || '',
        referredBy: account.referredBy?.toString?.() || '',
        cartItems: cartItemsPreview.map((item) => ({
          productId: item.productId.toString(),
          quantity: item.quantity
        })),
        cartItemCount: accountCollections?.cartItemCount || 0,
        wishlistProductIds: wishlistPreview.map((id) => id.toString()),
        wishlistCount: accountCollections?.wishlistCount || 0,
        referralSource,
        createdAt: account.createdAt,
        updatedAt: account.updatedAt
      },
      seller: sellerShop ? {
        id: sellerShop._id.toString(),
        name: sellerShop.name,
        slug: sellerShop.slug,
        description: sellerShop.description,
        coverImageUrl: sellerShop.coverImageUrl,
        town: sellerShop.town,
        approvalStatus: sellerShop.approvalStatus,
        approvalNote: sellerShop.approvalNote,
        sellerSuspended: isSellerInventoryRestricted(sellerShop),
        sellerRestrictionStatus: sellerShop.sellerRestrictionStatus || 'active',
        sellerRestrictedUntil: sellerShop.sellerRestrictedUntil,
        sellerRestrictionLastTriggeredAt: sellerShop.sellerRestrictionLastTriggeredAt,
        sellerRestrictionReason: sellerShop.sellerRestrictionReason,
        autoApprovalEnabled: sellerShop.autoApprovalEnabled,
        shippingRates: sellerShop.shippingRates,
        assistantPlanActive: sellerShop.assistantPlanActive,
        assistantPlanPaidAt: sellerShop.assistantPlanPaidAt,
        assistantEnabled: sellerShop.assistantEnabled,
        kycStatus: sellerShop.kycStatus || 'not_submitted',
        kycBusinessName: sellerShop.kycBusinessName || '',
        kycDocumentType: sellerShop.kycDocumentType || '',
        kycDocumentMime: sellerShop.kycDocumentMime || '',
        kycDocumentAvailable: Boolean(sellerShop.kycDocumentId),
        kycDocumentUrl: sellerShop.kycStatus === 'pending' && sellerShop.kycDocumentId
          ? `/api/admin/kyc/${sellerShop._id}/document`
          : '',
        kycSubmittedAt: sellerShop.kycSubmittedAt,
        kycReviewedAt: sellerShop.kycReviewedAt,
        kycReviewedBy: sellerShop.kycReviewedBy?.toString?.() || '',
        kycReviewNote: sellerShop.kycReviewNote || '',
        createdAt: sellerShop.createdAt,
        updatedAt: sellerShop.updatedAt
      } : null,
      activity: {
        buyerOrders: buyerOrderCount,
        sellerOrders: sellerOrderCount,
        listings: listingCount,
        reviews: reviewCount,
        listingReports: submittedReportCount,
        reportsOnListings: listingReportCount,
        listingModerationEvents: listingModerationEventCount,
        submittedReportModerationEvents: submittedReportModerationCount,
        listingThresholdEvents: thresholdEventCount,
        supportRequests: supportRequestCount,
        loginActivities: loginActivityCount,
        appeals: appealCount,
        notifications: notificationCount,
        sellerNotifications: sellerNotificationCount,
        supportNotifications: supportNotificationCount,
        statements: statementCount,
        sessions: sessionCount,
        passwordResetRequests: passwordResetCount,
        emailVerificationRequests: emailVerificationCount,
        suspensionAppealAccessRequests: appealAccessCount,
        reviewsReceived: receivedReviewCount,
        developerApplications: developerApplicationCount
      },
      balances: {
        currentWalletNAD: roundNAD(account.walletBalanceNAD || 0),
        buyerPurchasesNAD: roundNAD(paidBuyerTotals[0]?.totalNAD || 0),
        buyerPaidOrderCount: paidBuyerTotals[0]?.count || 0,
        sellerPayout: {
          totalNAD: roundNAD(sellerPayoutSummary.totalPayoutNAD),
          creditedToWalletNAD: roundNAD(sellerPayoutSummary.creditedToWalletNAD),
          awaitingWalletCreditNAD: roundNAD(sellerPayoutSummary.awaitingWalletCreditNAD),
          orderCount: sellerPayoutSummary.orderCount
        },
        walletLedger: walletTotalsByType
      },
      transactions: {
        buyerOrders: buyerOrderCount,
        sellerOrders: sellerOrderCount,
        wallet: walletTransactionCount,
        payouts: payoutRequestCount,
        promotions: promotionCount,
        referrals: referralCount
      },
      records: {
        counts: {
          cart: accountCollections?.cartItemCount || 0,
          wishlist: accountCollections?.wishlistCount || 0,
          listings: listingCount,
          reviewsWritten: reviewCount,
          listingReports: submittedReportCount,
          reportsOnListings: listingReportCount,
          listingModeration: listingModerationEventCount,
          listingEngagement: listingEngagementCount,
          supportRequests: supportRequestCount,
          loginActivity: loginActivityCount,
          appeals: appealCount,
          notifications: notificationCount,
          sellerNotifications: sellerNotificationCount,
          developerApplications: developerApplicationCount,
          developerUsage: developerUsageCount,
          statements: statementCount,
          accountAudit: accountAuditCount,
          submittedReportModeration: submittedReportModerationCount,
          listingReviewActions: listingReviewActionCount,
          reviewsReceived: receivedReviewCount,
          thresholdEvents: thresholdEventCount,
          supportNotifications: supportNotificationCount,
          sessions: sessionCount,
          passwordResets: passwordResetCount,
          emailVerifications: emailVerificationCount,
          appealAccess: appealAccessCount,
          referrals: referralCount
        },
        referralSource,
        cart: cartItemsPreview.map((item) => {
          const product = cartProducts.find((entry) => entry._id.toString() === item.productId.toString());
          return {
            ...(product || {}),
            title: product?.title || 'Listing unavailable',
            productId: item.productId.toString(),
            quantity: item.quantity,
            status: product?.status || 'unavailable'
          };
        }),
        wishlist: wishlistPreview.map((productId) => {
          const product = cartProducts.find((entry) => entry._id.toString() === productId.toString());
          return {
            ...(product || {}),
            title: product?.title || 'Listing unavailable',
            productId: productId.toString(),
            status: product?.status || 'unavailable'
          };
        }),
        referrals: referredUsers,
        listings,
        reviews: reviews.map((review) => ({
          shopName: review.shopId?.name || 'Shop unavailable',
          rating: review.rating,
          comment: review.comment,
          createdAt: review.createdAt,
          updatedAt: review.updatedAt
        })),
        listingReports: submittedReports.map((report) => ({
          productTitle: report.productId?.title || 'Listing unavailable',
          reviewedBy: report.reviewedBy?.name || '',
          reason: report.reason,
          details: report.details,
          status: report.status,
          credibilityPoints: report.credibilityPoints,
          verifiedBuyer: report.verifiedBuyer,
          sellerReporter: report.sellerReporter,
          createdAt: report.createdAt,
          reviewedAt: report.reviewedAt
        })),
        supportRequests,
        loginActivities,
        appeals,
        notifications,
        sellerNotifications,
        reportsOnListings: reportsOnListings.map((report) => ({
          productTitle: report.productId?.title || 'Listing unavailable',
          reporterName: report.reporterId?.name || 'Unknown user',
          reviewedBy: report.reviewedBy?.name || '',
          reason: report.reason,
          details: report.details,
          status: report.status,
          createdAt: report.createdAt,
          reviewedAt: report.reviewedAt
        })),
        listingModerationEvents: listingModerationEvents.map((event) => ({
          action: event.action,
          details: event.details,
          targetLabel: event.targetLabel,
          actorType: event.actorType,
          actorName: event.actorId?.name || '',
          createdAt: event.createdAt
        })),
        listingEngagement: listingEngagement.map((entry) => ({
          campaignId: entry._id.campaignId,
          date: entry._id.date,
          eventType: entry._id.eventType,
          placement: entry._id.placement,
          count: entry.count
        })),
        accountAuditEvents: accountAuditEvents.map((event) => ({
          action: event.action,
          details: event.details,
          targetType: event.targetType,
          targetId: event.targetId,
          targetLabel: event.targetLabel,
          actorType: event.actorType,
          actorName: event.actorId?.name || '',
          createdAt: event.createdAt
        })),
        submittedReportModerationEvents: submittedReportModerationEvents.map((event) => ({
          action: event.action,
          details: event.details,
          targetId: event.targetId,
          targetLabel: event.targetLabel,
          actorType: event.actorType,
          actorName: event.actorId?.name || '',
          createdAt: event.createdAt
        })),
        listingReviewActions: listingReviewActions.map((report) => ({
          productTitle: report.productId?.title || 'Listing unavailable',
          reporterName: report.reporterId?.name || 'Unknown user',
          reason: report.reason,
          status: report.status,
          createdAt: report.createdAt,
          reviewedAt: report.reviewedAt
        })),
        receivedReviews: receivedReviews.map((review) => ({
          reviewerName: review.userId?.name || 'Account unavailable',
          reviewerEmail: review.userId?.email || '',
          rating: review.rating,
          comment: review.comment,
          createdAt: review.createdAt,
          updatedAt: review.updatedAt
        })),
        thresholdEvents,
        payoutBankAccount: account.payoutBankAccount ? {
          bankName: account.payoutBankAccount.bankName || '',
          accountName: account.payoutBankAccount.accountName || '',
          accountLast4: account.payoutBankAccount.accountLast4 || ''
        } : null,
        dismissedListingReportCount: account.dismissedListingReportCount || 0,
        statements: statements.map(({ statementId, snapshot, createdAt, updatedAt }) => ({
          statementId,
          snapshot,
          createdAt,
          updatedAt
        })),
        security: {
          sessions,
          passwordResetRequests: passwordResets,
          emailVerificationRequests: emailVerifications,
          suspensionAppealAccessRequests: appealAccessRecords
        },
        supportNotifications,
        developerUsageRecords,
        developerApplications: developerApplications.map((application) => {
          const usage = usageByApplication.get(application.appId);
          return {
            appId: application.appId,
            name: application.name,
            tokenLast4: application.tokenLast4,
            revokedAt: application.revokedAt,
            lastUsedAt: application.lastUsedAt,
            createdAt: application.createdAt,
            updatedAt: application.updatedAt,
            usage: {
              requests: usage?.requests || 0,
              verified: usage?.verified || 0,
              mismatched: usage?.mismatched || 0,
              lastActivity: usage?.lastActivity || null
            }
          };
        })
      }
    }
  });
});

function normalizeAdminNotificationInput(input) {
  const title = typeof input?.title === 'string' ? input.title.trim() : '';
  const message = typeof input?.message === 'string' ? input.message.trim() : '';
  const audience = input?.audience;
  const recipientIds = input?.recipientIds;
  const destination = input?.destination === undefined ? 'both' : input.destination;
  if (!title || title.length > 120 || !message || message.length > 1000) {
    return { error: 'Enter a title (up to 120 characters) and message (up to 1,000 characters).' };
  }
  if (!['all', 'selected'].includes(audience)) {
    return { error: 'Choose all accounts or selected accounts.' };
  }
  if (!['account', 'seller', 'both'].includes(destination)) {
    return { error: 'Choose the account dashboard, seller workspace, or both as the destination.' };
  }
  if (audience !== 'selected') {
    if (recipientIds !== undefined && (!Array.isArray(recipientIds) || recipientIds.length > 0)) {
      return { error: 'Individual accounts can only be included for a selected-account notification.' };
    }
    return { title, message, audience, destination, recipientIds: [] };
  }
  if (!Array.isArray(recipientIds) || recipientIds.length < 1 || recipientIds.length > 100
    || recipientIds.some((id) => typeof id !== 'string' || !mongoose.isValidObjectId(id))) {
    return { error: 'Select between 1 and 100 valid accounts.' };
  }
  const uniqueIds = [...new Set(recipientIds.map((id) => id.toString()))];
  if (uniqueIds.length > 100) return { error: 'Select between 1 and 100 valid accounts.' };
  return { title, message, audience, destination, recipientIds: uniqueIds };
}

app.post('/api/admin/notifications', async (req, res) => {
  const admin = await getSessionUser(req);
  if (!admin || !isAdminUser(admin)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });

  const input = normalizeAdminNotificationInput(req.body);
  if (input.error) return res.status(400).json({ error: input.error });

  let recipientIds;
  if (input.audience === 'all') {
    recipientIds = await User.find({}).distinct('_id');
  } else {
    const matchedUsers = await User.find({ _id: { $in: input.recipientIds } }).select('_id').lean();
    if (matchedUsers.length !== input.recipientIds.length) {
      return res.status(400).json({ error: 'One or more selected accounts could not be found. Refresh the account search and try again.' });
    }
    recipientIds = matchedUsers.map((account) => account._id);
  }

  if (input.destination === 'seller') {
    const sellerIds = await Shop.distinct('ownerId', { ownerId: { $in: recipientIds } });
    if (sellerIds.length !== recipientIds.length) {
      return res.status(400).json({ error: 'Seller workspace delivery is only available to seller accounts. Choose seller accounts or select only sellers.' });
    }
  }

  let deliveredCount = 0;
  for (let index = 0; index < recipientIds.length; index += 500) {
    const batch = recipientIds.slice(index, index + 500).map((userId) => ({
      userId,
      createdBy: admin._id,
      title: input.title,
      message: input.message,
      destination: input.destination
    }));
    try {
      await AccountNotification.insertMany(batch, { ordered: true });
      deliveredCount += batch.length;
    } catch (error) {
      console.error(`Admin notification delivery failed after ${deliveredCount} of ${recipientIds.length} recipients:`, error.message);
      return res.status(500).json({
        error: deliveredCount
          ? `Notification delivery stopped after reaching ${deliveredCount} of ${recipientIds.length} accounts.`
          : 'Notification could not be delivered.',
        deliveredCount
      });
    }
  }
  return res.status(201).json({ ok: true, deliveredCount });
});

app.get('/api/admin/users/:id/activity', async (req, res) => {
  const admin = await getSessionUser(req);
  if (!admin || !isAdminUser(admin)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Account not found.' });

  const account = await User.findById(req.params.id)
    .select('name email role emailVerified isSuspended dismissedListingReportCount walletBalanceNAD createdAt')
    .lean();
  if (!account) return res.status(404).json({ error: 'Account not found.' });

  const now = new Date();
  const [shops, loginActivities, submittedReports, submittedStats, supportRequests, appeals, accountActions, buyerOrders, sellerOrders, reviewsWritten, referrals, walletLedgerSummary] = await Promise.all([
    Shop.find({ ownerId: account._id }).select('_id name sellerSuspended sellerRestrictionStatus sellerRestrictedUntil sellerRestrictionReason approvalStatus').lean(),
    LoginActivity.find({ userId: account._id, expiresAt: { $gt: now } })
      .sort({ createdAt: -1 }).limit(25)
      .select('device client_ip country_code city isp_provider createdAt').lean(),
    ListingReport.find({ reporterId: account._id })
      .sort({ createdAt: -1 }).limit(50)
      .populate('productId', 'title').select('productId reason details credibilityPoints verifiedBuyer sellerReporter status createdAt reviewedAt').lean(),
    ListingReport.aggregate([
      { $match: { reporterId: account._id } },
      { $group: {
        _id: '$status',
        count: { $sum: 1 },
        credibilityPoints: { $sum: { $ifNull: ['$credibilityPoints', 5] } }
      } }
    ]),
    SupportRequest.find({ buyerId: account._id }).sort({ createdAt: -1 }).limit(25)
      .select('topic message status createdAt updatedAt').lean(),
    SuspensionAppeal.find({ accountEmail: account.email }).sort({ createdAt: -1 }).limit(25)
      .select('reason referenceId status createdAt updatedAt').lean(),
    ModerationAudit.find({ targetType: 'account', targetId: account._id.toString() })
      .sort({ createdAt: -1 }).limit(25).select('action details createdAt actorId actorType').lean(),
    Order.find({ buyerId: account._id }).sort({ createdAt: -1 }).limit(25)
      .select('orderNumber paymentStatus totalNAD createdAt').lean(),
    Order.aggregate([
      { $unwind: '$sellerOrders' },
      { $match: { 'sellerOrders.sellerId': account._id } },
      { $sort: { createdAt: -1 } },
      { $limit: 100 },
      { $project: {
        orderNumber: 1,
        paymentStatus: 1,
        createdAt: 1,
        shopName: '$sellerOrders.shopName',
        approvalStatus: '$sellerOrders.approvalStatus',
        fulfillmentStatus: '$sellerOrders.fulfillmentStatus',
        payoutStatus: '$sellerOrders.payoutStatus',
        payoutNAD: '$sellerOrders.payoutNAD'
      } }
    ]),
    ShopReview.countDocuments({ userId: account._id }),
    User.countDocuments({ referredBy: account._id }),
    getWalletLedgerSummary(account._id)
  ]);
  const walletReconciliation = reconcileWalletBalance(account.walletBalanceNAD || 0, walletLedgerSummary);
  const { adminNotified } = await updateWalletReconciliationAlert(admin, account, walletReconciliation);
  const shopIds = shops.map((shop) => shop._id);
  const [receivedReportStats, receivedReports, reportHiddenListings] = shopIds.length
    ? await Promise.all([
      ListingReport.aggregate([
        { $lookup: { from: Product.collection.name, localField: 'productId', foreignField: '_id', as: 'product' } },
        { $unwind: '$product' },
        { $match: { 'product.shopId': { $in: shopIds } } },
        { $group: {
          _id: '$status',
          count: { $sum: 1 },
          credibilityPoints: { $sum: { $ifNull: ['$credibilityPoints', 5] } }
        } }
      ]),
      ListingReport.aggregate([
        { $lookup: { from: Product.collection.name, localField: 'productId', foreignField: '_id', as: 'product' } },
        { $unwind: '$product' },
        { $match: { 'product.shopId': { $in: shopIds } } },
        { $sort: { createdAt: -1 } },
        { $limit: 50 },
        { $lookup: { from: User.collection.name, localField: 'reporterId', foreignField: '_id', as: 'reporter' } },
        { $unwind: { path: '$reporter', preserveNullAndEmptyArrays: true } },
        { $project: {
          product: '$product.title',
          reporter: { $ifNull: ['$reporter.name', 'Account unavailable'] },
          reason: 1,
          details: 1,
          credibilityPoints: { $ifNull: ['$credibilityPoints', 5] },
          status: 1,
          createdAt: 1,
          reviewedAt: 1
        } }
      ]),
      Product.countDocuments({ shopId: { $in: shopIds }, moderationSource: 'report_threshold' })
    ])
    : [[], [], 0];
  const submittedStatsByStatus = Object.fromEntries(submittedStats.map((entry) => [entry._id, entry]));
  const receivedStatsByStatus = Object.fromEntries(receivedReportStats.map((entry) => [entry._id, entry]));
  const submittedReportCount = Object.values(submittedStatsByStatus).reduce((sum, entry) => sum + entry.count, 0);
  const receivedReportCount = Object.values(receivedStatsByStatus).reduce((sum, entry) => sum + entry.count, 0);

  return res.json({
    account: {
      id: account._id.toString(),
      name: account.name,
      email: account.email,
      role: getPublicRole(account),
      emailVerified: Boolean(account.emailVerified),
      isSuspended: Boolean(account.isSuspended),
      walletBalanceNAD: roundNAD(account.walletBalanceNAD || 0),
      createdAt: account.createdAt
    },
    financialReconciliation: {
      ...walletReconciliation,
      adminNotified
    },
    riskSignals: {
      dismissedReportCount: account.dismissedListingReportCount || 0,
      reportingPaused: isListingReportBlocked(account.dismissedListingReportCount || 0),
      submittedReportCount,
      dismissedSubmittedReportCount: submittedStatsByStatus.dismissed?.count || 0,
      submittedCredibilityPoints: Object.values(submittedStatsByStatus).reduce((sum, entry) => sum + entry.credibilityPoints, 0),
      receivedReportCount,
      pendingReportsOnListings: receivedStatsByStatus.pending?.count || 0,
      pendingReportPointsOnListings: receivedStatsByStatus.pending?.credibilityPoints || 0,
      dismissedReportsOnListings: receivedStatsByStatus.dismissed?.count || 0,
      reportHiddenListings,
      sellerRestrictionStatus: shops[0]?.sellerRestrictionStatus || 'active',
      sellerRestrictedUntil: shops[0]?.sellerRestrictedUntil || null,
      sellerRestrictionActive: isSellerAutoRestricted(shops[0])
    },
    activity: {
      loginActivities: loginActivities.map((entry) => ({
        device: entry.device,
        clientIp: entry.client_ip,
        countryCode: entry.country_code,
        city: entry.city,
        ispProvider: entry.isp_provider,
        createdAt: entry.createdAt
      })),
      submittedReports: submittedReports.map((entry) => ({
        product: entry.productId?.title || 'Listing unavailable',
        reason: entry.reason,
        details: entry.details,
        credibilityPoints: entry.credibilityPoints ?? 5,
        verifiedBuyer: Boolean(entry.verifiedBuyer),
        sellerReporter: Boolean(entry.sellerReporter),
        status: entry.status,
        createdAt: entry.createdAt,
        reviewedAt: entry.reviewedAt
      })),
      receivedReports: receivedReports.map((entry) => ({
        product: entry.product || 'Listing unavailable',
        reporter: entry.reporter || 'Account unavailable',
        reason: entry.reason,
        details: entry.details,
        credibilityPoints: entry.credibilityPoints ?? 5,
        status: entry.status,
        createdAt: entry.createdAt,
        reviewedAt: entry.reviewedAt
      })),
      supportRequests: supportRequests.map((entry) => ({
        topic: entry.topic,
        message: entry.message,
        status: entry.status,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      })),
      appeals: appeals.map((entry) => ({
        reason: entry.reason,
        referenceId: entry.referenceId,
        status: entry.status,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      })),
      accountActions: accountActions.map((entry) => ({
        action: entry.action,
        details: entry.details,
        createdAt: entry.createdAt,
        actorId: entry.actorId?.toString() || null,
        actorType: entry.actorType
      })),
      buyerOrders: buyerOrders.map((entry) => ({
        orderNumber: entry.orderNumber,
        paymentStatus: entry.paymentStatus,
        totalNAD: entry.totalNAD,
        createdAt: entry.createdAt
      })),
      sellerOrders: sellerOrders.map((entry) => ({
        orderNumber: entry.orderNumber,
        paymentStatus: entry.paymentStatus,
        shopName: entry.shopName,
        approvalStatus: entry.approvalStatus,
        fulfillmentStatus: entry.fulfillmentStatus,
        payoutStatus: entry.payoutStatus,
        payoutNAD: entry.payoutNAD,
        createdAt: entry.createdAt
      })),
      shops: shops.map((shop) => ({
        name: shop.name,
        sellerSuspended: Boolean(shop.sellerSuspended),
        sellerRestrictionStatus: shop.sellerRestrictionStatus || 'active',
        sellerRestrictedUntil: shop.sellerRestrictedUntil || null,
        sellerRestrictionReason: shop.sellerRestrictionReason || '',
        approvalStatus: shop.approvalStatus
      })),
      reviewsWritten,
      referrals
    }
  });
});

app.patch('/api/admin/users/:id/role', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user || !isAdminUser(user)) return res.status(403).json({ error: 'Super-admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Account not found.' });
  const role = req.body?.role;
  if (!['customer', 'moderator'].includes(role)) return res.status(400).json({ error: 'Choose customer or moderator access.' });
  const account = await User.findById(req.params.id);
  if (!account || isConfiguredAdminIdentity(account) || account.role === 'sandbox' || isSandboxUser(account)) {
    return res.status(404).json({ error: 'Eligible account not found.' });
  }
  if (role === 'moderator' && !isEmailVerified(account)) {
    return res.status(409).json({ error: 'Verify this account email before granting moderator access.' });
  }
  if (role === 'moderator' && account.role !== 'moderator' && await User.countDocuments({ role: 'moderator', isSuspended: { $ne: true } }) >= 3) {
    return res.status(409).json({ error: 'The platform supports up to three moderator accounts.' });
  }
  account.role = role;
  await account.save();
  return res.json({ ok: true, role: account.role });
});

app.patch('/api/admin/users/:id/status', async (req, res) => {
  const moderator = await getSessionUser(req);
  if (!moderator || !isAdminUser(moderator)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Account not found.' });
  if (typeof req.body?.isSuspended !== 'boolean') return res.status(400).json({ error: 'Choose whether the account should be suspended.' });

  const account = await User.findById(req.params.id);
  if (!account) return res.status(404).json({ error: 'Account not found.' });
  if (isConfiguredAdminIdentity(account)) return res.status(403).json({ error: 'The configured super-admin account cannot be suspended.' });

  const previousStatus = Boolean(account.isSuspended);
  account.isSuspended = req.body.isSuspended;
  await account.save();
  if (account.isSuspended) await Session.deleteMany({ userId: account._id });
  if (previousStatus !== account.isSuspended) {
    await recordModerationAudit({
      actorId: moderator._id,
      action: account.isSuspended ? 'account_suspended' : 'account_reactivated',
      targetType: 'account',
      targetId: account._id.toString(),
      targetLabel: `${account.name} (${account.email})`,
      details: account.isSuspended ? 'Account suspension confirmed by Super Admin.' : 'Account reactivation confirmed by Super Admin.'
    });
  }
  return res.json({
    user: {
      id: account._id.toString(),
      isSuspended: account.isSuspended
    },
    message: account.isSuspended
      ? 'Account suspended. Active sessions have been signed out.'
      : 'Account reactivated. The user can sign in again.'
  });
});

app.patch('/api/admin/users/:id/seller-status', async (req, res) => {
  const moderator = await getSessionUser(req);
  if (!moderator || !isAdminUser(moderator)) return res.status(403).json({ error: 'Admin access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Seller account not found.' });
  if (typeof req.body?.sellerSuspended !== 'boolean') return res.status(400).json({ error: 'Choose whether seller access should be suspended.' });

  const account = await User.findById(req.params.id);
  if (!account) return res.status(404).json({ error: 'Seller account not found.' });
  if (isConfiguredAdminIdentity(account)) return res.status(403).json({ error: 'The configured super-admin account cannot be suspended.' });

  const shop = await Shop.findOne({ ownerId: account._id });
  if (!shop) return res.status(404).json({ error: 'Seller storefront not found.' });
  const previousStatus = isSellerInventoryRestricted(shop);
  shop.sellerSuspended = req.body.sellerSuspended;
  if (!req.body.sellerSuspended) {
    shop.sellerRestrictionStatus = 'active';
    shop.sellerRestrictedUntil = null;
    shop.sellerRestrictionReason = '';
  }
  await shop.save();
  const currentStatus = isSellerInventoryRestricted(shop);
  if (previousStatus !== currentStatus) {
    await recordModerationAudit({
      actorId: moderator._id,
      actorType: 'admin',
      action: currentStatus ? 'seller_access_suspended' : 'seller_access_reactivated',
      targetType: 'account',
      targetId: account._id.toString(),
      targetLabel: `${account.name} (${account.email})`,
      details: currentStatus
        ? `Seller access suspended for shop ${shop.name} (${shop._id.toString()}).`
        : `Seller access reactivated for shop ${shop.name} (${shop._id.toString()}).`
    });
  }
  return res.json({
    user: {
      id: account._id.toString(),
      sellerSuspended: currentStatus,
      sellerRestrictionStatus: shop.sellerRestrictionStatus,
      sellerRestrictedUntil: shop.sellerRestrictedUntil
    },
    message: currentStatus
      ? 'Seller access suspended. The shop and listings are hidden; buyer access remains available.'
      : 'Seller access restored. The shop and listings are visible again; buyer access was unchanged.'
  });
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
  if (!user || !isModeratorUser(user)) return res.status(403).json({ error: 'Moderator access is not configured for this account.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Product not found.' });
  const decision = req.body?.decision;
  if (!['hide', 'restore'].includes(decision)) return res.status(400).json({ error: 'Choose whether to hide or restore this listing.' });

  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ error: 'Product not found.' });
  product.moderationStatus = decision === 'hide' ? 'hidden' : 'visible';
  product.moderationSource = decision === 'hide' ? 'moderator' : null;
  product.moderatedAt = decision === 'hide' ? new Date() : null;
  await product.save();
  await recordModerationAudit({
    actorId: user._id,
    action: decision === 'hide' ? 'listing_hidden' : 'listing_restored',
    targetType: 'listing',
    targetId: product._id.toString(),
    targetLabel: product.title,
    details: 'Manual moderator action from the listing review queue.'
  });

  return res.json({ ok: true, productId: product._id.toString(), moderationStatus: product.moderationStatus });
});

app.get('/api/products', async (req, res) => {
  await releaseExpiredReservations();
  const now = new Date();
  await PromotionCampaign.updateMany(
    { status: 'active', expiresAt: { $lte: now } },
    { $set: { status: 'expired' } }
  );
  const promotedProductIds = await PromotionCampaign.distinct('productId', {
    status: 'active',
    expiresAt: { $gt: now }
  });
  const { q = '', category = '', town = '' } = req.query;
  if (typeof q !== 'string' || q.length > 80 || (category && !productCategories.includes(category)) || (town && !namibianTowns.includes(town))) {
    return res.status(400).json({ error: 'Invalid marketplace filters.' });
  }

  const unavailableShopIds = await getUnavailableShopIds();
  const filter = {
    shopId: { $nin: unavailableShopIds },
    _id: { $nin: promotedProductIds },
    status: 'active',
    isAvailable: { $ne: false },
    reviewStatus: { $in: ['approved', null] },
    moderationStatus: { $ne: 'hidden' }
  };
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

function serializeLoginWallpaper(setting) {
  const settings = { ...DEFAULT_LOGIN_WALLPAPER };
  for (const key of Object.keys(settings)) {
    if (key === 'productIds') {
      settings.productIds = Array.isArray(setting?.productIds) && setting.productIds.length
        ? setting.productIds.map((id) => id.toString())
        : setting?.productId ? [setting.productId.toString()] : [];
    } else if (key === 'rotatePromotions') {
      settings.rotatePromotions = typeof setting?.rotatePromotions === 'boolean'
        ? setting.rotatePromotions
        : !setting?.productId;
    } else if (setting?.[key] !== undefined) {
      settings[key] = setting[key];
    }
  }
  return settings;
}

async function getActivePromotedProducts() {
  const now = new Date();
  await PromotionCampaign.updateMany(
    { status: 'active', expiresAt: { $lte: now } },
    { $set: { status: 'expired' } }
  );
  const campaigns = await PromotionCampaign.find({
    status: 'active',
    startsAt: { $lte: now },
    expiresAt: { $gt: now }
  }).sort({ paidAt: -1 }).limit(24)
    .populate({ path: 'productId', match: { status: 'active', isAvailable: { $ne: false }, stock: { $gt: 0 }, reviewStatus: { $in: ['approved', null] }, moderationStatus: { $ne: 'hidden' } } })
    .populate({ path: 'shopId', match: getPublicShopFilter(now), select: 'name slug' })
    .lean();
  return campaigns.flatMap((campaign) => {
    const product = campaign.productId;
    const shop = campaign.shopId;
    if (!product || !shop) return [];
    return [{
      id: product._id.toString(),
      campaignId: campaign._id.toString(),
      title: product.title,
      description: product.description,
      priceNAD: product.priceNAD,
      stock: product.stock ?? null,
      category: product.category,
      town: product.town,
      imageUrl: product.imageUrl || '',
      shopName: shop.name,
      shopSlug: shop.slug,
      promoted: true,
      promotionExpiresAt: campaign.expiresAt
    }];
  });
}

app.get('/api/promotions/active', async (req, res) => {
  return res.json({ products: await getActivePromotedProducts() });
});

app.get('/api/login-wallpaper', async (req, res) => {
  const saved = await LoginWallpaper.findOne({ key: 'login' }).lean();
  res.set('Cache-Control', 'no-store');
  return res.json({ settings: serializeLoginWallpaper(saved) });
});

app.post('/api/promotions/:id/engagement', promotionEngagementRateLimit, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Promotion not found.' });
  const { eventType, placement } = req.body || {};
  const visitorId = normalizePromotionVisitorId(req.body?.visitorId);
  if (!['impression', 'click'].includes(eventType) || !['marketplace', 'dashboard'].includes(placement) || !visitorId) {
    return res.status(400).json({ error: 'Invalid promotion engagement event.' });
  }

  const now = new Date();
  const campaign = await PromotionCampaign.findOne({
    _id: req.params.id,
    status: 'active',
    startsAt: { $lte: now },
    expiresAt: { $gt: now }
  }).select('_id shopId productId');
  if (!campaign) return res.status(404).json({ error: 'Active promotion not found.' });
  const [eligibleProduct, visibleShop] = await Promise.all([
    Product.exists({
      _id: campaign.productId,
      shopId: campaign.shopId,
      status: 'active',
      isAvailable: { $ne: false },
      stock: { $gt: 0 },
      reviewStatus: { $in: ['approved', null] },
      moderationStatus: { $ne: 'hidden' }
    }),
    Shop.exists({ _id: campaign.shopId, ...getPublicShopFilter(now) })
  ]);
  if (!eligibleProduct || !visibleShop) return res.status(404).json({ error: 'Active promotion not found.' });

  const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const visitorHash = createHash('sha256')
    .update(`${campaign._id}:${placement}:${date.toISOString()}:${visitorId}`)
    .digest('hex');
  try {
    await PromotionEngagement.create({
      campaignId: campaign._id,
      shopId: campaign.shopId,
      eventType,
      placement,
      date,
      visitorHash
    });
    return res.status(202).json({ recorded: true });
  } catch (error) {
    if (error.code === 11000) return res.status(202).json({ recorded: false });
    throw error;
  }
});

app.get('/api/seller/billing', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view billing history.' });
  const shop = await Shop.findOne({ ownerId: user._id }).select('_id').lean();
  if (!shop) return res.status(404).json({ error: 'Seller shop not found.' });

  const campaigns = await PromotionCampaign.find({ shopId: shop._id })
    .sort({ createdAt: -1 })
    .limit(200)
    .populate({ path: 'productId', select: 'title' })
    .lean();
  const entries = campaigns.map((campaign) => ({
    id: campaign._id.toString(),
    productName: campaign.productId?.title || 'Deleted listing',
    amountNAD: campaign.amountNAD,
    status: campaign.status,
    paymentMethod: campaign.paymentMethod,
    walletUsedNAD: campaign.walletUsedNAD || 0,
    cardDueNAD: campaign.cardDueNAD || 0,
    paidAt: campaign.paidAt,
    createdAt: campaign.createdAt,
    startsAt: campaign.startsAt,
    expiresAt: campaign.expiresAt
  }));
  const paidEntries = entries.filter((entry) => entry.paidAt);
  return res.json({
    entries,
    hasMore: campaigns.length === 200,
    totals: {
      paidNAD: roundNAD(paidEntries.reduce((total, entry) => total + entry.amountNAD, 0)),
      walletNAD: roundNAD(paidEntries.reduce((total, entry) => total + entry.walletUsedNAD, 0)),
      cardNAD: roundNAD(paidEntries.reduce((total, entry) => total + entry.cardDueNAD, 0)),
      paidCount: paidEntries.length
    }
  });
});

app.get('/api/seller/promotions/stats', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to view promotion statistics.' });
  const shop = await Shop.findOne({ ownerId: user._id }).select('_id');
  if (!shop) return res.json({ campaigns: [], daily: [] });

  const now = new Date();
  await PromotionCampaign.updateMany(
    { shopId: shop._id, status: 'active', expiresAt: { $lte: now } },
    { $set: { status: 'expired' } }
  );
  const campaigns = await PromotionCampaign.find({
    shopId: shop._id,
    status: { $in: ['active', 'expired'] }
  }).sort({ paidAt: -1 }).limit(100)
    .populate({ path: 'productId', select: 'title imageUrl' })
    .lean();

  const periodStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  periodStart.setUTCDate(periodStart.getUTCDate() - 29);
  const campaignIds = campaigns.map((campaign) => campaign._id);
  const [campaignTotals, dailyTotals] = campaignIds.length ? await Promise.all([
    PromotionEngagement.aggregate([
      { $match: { shopId: shop._id, campaignId: { $in: campaignIds } } },
      { $group: { _id: { campaignId: '$campaignId', placement: '$placement', eventType: '$eventType' }, count: { $sum: 1 } } }
    ]),
    PromotionEngagement.aggregate([
      { $match: { shopId: shop._id, date: { $gte: periodStart } } },
      { $group: { _id: { date: '$date', placement: '$placement', eventType: '$eventType' }, count: { $sum: 1 } } }
    ])
  ]) : [[], []];

  const totalsByCampaign = new Map();
  campaignTotals.forEach(({ _id, count }) => {
    const metrics = totalsByCampaign.get(_id.campaignId.toString()) || {
      marketplaceImpressions: 0,
      marketplaceClicks: 0,
      dashboardImpressions: 0,
      dashboardClicks: 0
    };
    metrics[`${_id.placement}${_id.eventType === 'impression' ? 'Impressions' : 'Clicks'}`] = count;
    totalsByCampaign.set(_id.campaignId.toString(), metrics);
  });
  const dailyByDate = new Map();
  dailyTotals.forEach(({ _id, count }) => {
    const dateKey = _id.date.toISOString().slice(0, 10);
    const metrics = dailyByDate.get(dateKey) || {
      date: dateKey,
      marketplaceImpressions: 0,
      marketplaceClicks: 0,
      dashboardImpressions: 0,
      dashboardClicks: 0
    };
    metrics[`${_id.placement}${_id.eventType === 'impression' ? 'Impressions' : 'Clicks'}`] = count;
    dailyByDate.set(dateKey, metrics);
  });

  const daily = [];
  for (let day = new Date(periodStart); day <= now; day.setUTCDate(day.getUTCDate() + 1)) {
    const dateKey = day.toISOString().slice(0, 10);
    daily.push(dailyByDate.get(dateKey) || {
      date: dateKey,
      marketplaceImpressions: 0,
      marketplaceClicks: 0,
      dashboardImpressions: 0,
      dashboardClicks: 0
    });
  }
  return res.json({
    campaigns: campaigns.map((campaign) => {
      const metrics = totalsByCampaign.get(campaign._id.toString()) || {
        marketplaceImpressions: 0,
        marketplaceClicks: 0,
        dashboardImpressions: 0,
        dashboardClicks: 0
      };
      const impressions = metrics.marketplaceImpressions + metrics.dashboardImpressions;
      const clicks = metrics.marketplaceClicks + metrics.dashboardClicks;
      return {
        id: campaign._id.toString(),
        title: campaign.productId?.title || 'Deleted product',
        imageUrl: campaign.productId?.imageUrl || '',
        status: campaign.status,
        startsAt: campaign.startsAt,
        expiresAt: campaign.expiresAt,
        impressions,
        clicks,
        clickThroughRate: calculatePromotionClickThroughRate(impressions, clicks),
        ...metrics
      };
    }),
    daily
  });
});

app.get('/api/products/:id', async (req, res) => {
  await releaseExpiredReservations();
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Product not found.' });
  const product = await Product.findOne({ _id: req.params.id, status: 'active', isAvailable: { $ne: false }, reviewStatus: { $in: ['approved', null] }, moderationStatus: { $ne: 'hidden' } })
    .populate('shopId', 'name slug description town sellerSuspended approvalStatus sellerRestrictionStatus sellerRestrictedUntil')
    .lean();

  if (!product?.shopId || !isPublicSellerShop(product.shopId)) return res.status(404).json({ error: 'Product not found.' });
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

  const filter = getPublicShopFilter();
  if (town) filter.town = town;
  if (q.trim()) {
    const safeQuery = q.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    filter.$and.push({ $or: [
      { name: { $regex: safeQuery, $options: 'i' } },
      { description: { $regex: safeQuery, $options: 'i' } }
    ] });
  }

  const shops = await Shop.find(filter).sort({ name: 1 }).limit(100).lean();
  const shopIds = shops.map((shop) => shop._id);
  const counts = shopIds.length ? await Product.aggregate([
    { $match: { shopId: { $in: shopIds }, status: 'active', isAvailable: { $ne: false }, reviewStatus: { $in: ['approved', null] }, moderationStatus: { $ne: 'hidden' } } },
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
  const shop = await Shop.findOne({ slug: req.params.slug, ...getPublicShopFilter() }).lean();
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  const products = await Product.find({
    shopId: shop._id,
    status: 'active',
    isAvailable: { $ne: false },
    reviewStatus: { $in: ['approved', null] },
    moderationStatus: { $ne: 'hidden' }
  }).sort({ createdAt: -1 }).limit(100).lean();

  const reviews = await ShopReview.find({ shopId: shop._id }).sort({ createdAt: -1 }).populate('userId', 'name').lean();
  const reviewCount = reviews.length;
  const averageRating = reviewCount ? reviews.reduce((sum, review) => sum + review.rating, 0) / reviewCount : 0;
  const ownReview = viewer ? reviews.find((review) => review.userId && review.userId._id.toString() === viewer._id.toString()) || null : null;
  const assistantPlanPaid = isAssistantPlanPaid(shop);
  const assistantServiceConfigured = assistantPlanPaid && shop.assistantEnabled
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
      assistantAvailable: Boolean(assistantPlanPaid && shop.assistantEnabled && assistantServiceConfigured),
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
    const maxLength = item?.role === 'assistant' ? 2000 : 500;
    if (!['user', 'assistant'].includes(item?.role) || typeof item.content !== 'string' || item.content.length > maxLength) {
      return res.status(400).json({ error: 'The conversation could not be processed.' });
    }
    history.push({ role: item.role, content: item.content });
  }

  const shop = await Shop.findOne({
    slug: req.params.slug,
    ...getPublicShopFilter(),
    assistantPlanActive: true,
    assistantPlanPaidAt: { $ne: null },
    assistantEnabled: true
  }).lean();
  if (!shop) return res.status(404).json({ error: 'This shop assistant is not available.' });
  if (!await isAssistantModelReady()) return res.status(503).json({ error: 'The local AI model is not installed or Ollama is not running.' });

  const products = await Product.find({
    shopId: shop._id,
    status: 'active',
    isAvailable: { $ne: false },
    reviewStatus: { $in: ['approved', null] },
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

  const shop = await Shop.findOne({ slug: req.params.slug, ...getPublicShopFilter() }).select('_id');
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
    { returnDocument: 'after', upsert: true, runValidators: true, setDefaultsOnInsert: true }
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

app.post('/api/products/:id/reports', listingReportRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to report a listing.' });
  if (isListingReportBlocked(user.dismissedListingReportCount || 0)) {
    return res.status(403).json({
      error: 'Reporting is paused because three of your previous reports were dismissed as unfounded. Contact support if you believe this restriction is in error.'
    });
  }
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Listing not found.' });

  const unavailableShopIds = await getUnavailableShopIds();
  const product = await Product.findOne({
    _id: req.params.id,
    shopId: { $nin: unavailableShopIds },
    status: 'active',
    reviewStatus: { $in: ['approved', null] },
    moderationStatus: { $ne: 'hidden' }
  }).populate('shopId', 'ownerId')
    .select('_id shopId');
  if (!product?.shopId) return res.status(404).json({ error: 'Listing not found.' });
  if (product.shopId.ownerId.toString() === user._id.toString()) return res.status(403).json({ error: 'You cannot report your own listing.' });

  const reason = req.body?.reason;
  const details = typeof req.body?.details === 'string' ? req.body.details.trim() : '';
  if (!['misleading', 'counterfeit', 'unsafe', 'prohibited', 'other'].includes(reason) || details.length > 500) {
    return res.status(400).json({ error: 'Choose a report reason and keep details under 500 characters.' });
  }

  const sellerShop = await Shop.findOne({
    ownerId: user._id,
    approvalStatus: 'approved',
    sellerSuspended: { $ne: true }
  }).select('_id').lean();
  const sellerReporter = Boolean(sellerShop);
  if (sellerReporter && details.length < 20) {
    return res.status(400).json({ error: 'Shop owners must include at least 20 characters explaining their report.' });
  }
  const verifiedBuyer = !sellerReporter && Boolean(await Order.exists({
    buyerId: user._id,
    paymentStatus: 'paid',
    sellerOrders: {
      $elemMatch: {
        shopId: product.shopId._id,
        fulfillmentStatus: 'delivered',
        items: { $elemMatch: { productId: product._id } }
      }
    }
  }));
  const credibilityPoints = getListingReportCredibilityPoints({ verifiedBuyer, sellerReporter });

  try {
    await ListingReport.create({
      productId: product._id,
      reporterId: user._id,
      reason,
      details,
      credibilityPoints,
      verifiedBuyer,
      sellerReporter
    });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'You have already reported this listing.' });
    throw error;
  }

  const [reportStats] = await ListingReport.aggregate([
    { $match: { productId: product._id, status: 'pending' } },
    { $group: {
      _id: '$productId',
      count: { $sum: 1 },
      score: { $sum: { $ifNull: ['$credibilityPoints', 5] } }
    } }
  ]);
  const reportCount = reportStats?.count || 0;
  const reportScore = reportStats?.score || 0;
  const autoHidden = shouldAutoHideListing(reportScore);
  if (autoHidden) {
    const triggeredAt = new Date();
    const hidden = await Product.updateOne(
      { _id: product._id, moderationStatus: { $ne: 'hidden' } },
      { $set: { moderationStatus: 'hidden', moderationSource: 'report_threshold', moderatedAt: triggeredAt } }
    );
    if (hidden.modifiedCount > 0) {
      await ListingThresholdEvent.create({ shopId: product.shopId._id, productId: product._id, triggeredAt });
      await applyAutomaticSellerRestriction(product.shopId._id, triggeredAt);
    }
  }
  return res.status(201).json({
    received: true,
    autoHidden,
    reportCount,
    reportScore,
    message: autoHidden
      ? 'Report received. This listing reached the review threshold and is temporarily hidden for moderator review.'
      : 'Report received for moderator review. Reports from confirmed buyers are prioritized; every report remains available for moderator review.'
  });
});

app.get('/api/seller/shop', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to manage your shop.' });
  const shop = await Shop.findOne({ ownerId: user._id }).select('-kycDocumentId -kycDocumentMime -kycReviewedBy').lean();
  return res.json({
    shop,
    assistantServiceConfigured: await isAssistantModelReady(),
    assistantPurchaseSimulationAvailable: mockPaymentsEnabled,
    assistantPriceNAD
  });
});

app.get('/api/seller/shop/verification', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to manage business verification.' });
  const shop = await Shop.findOne({ ownerId: user._id }).select('name kycStatus kycBusinessName kycDocumentType kycSubmittedAt kycReviewedAt kycReviewNote').lean();
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  const { name, ...verification } = shop;
  return res.json({ verification, shopName: name, storageConfigured: isKycStorageConfigured() });
});

app.post('/api/seller/shop/verification', kycSubmissionRateLimit, async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to submit business verification.' });
  if (!isKycStorageConfigured()) return res.status(503).json({ error: 'Business verification uploads are disabled until durable encrypted storage is configured.' });

  let encryptionKey;
  try {
    encryptionKey = getKycEncryptionKey();
  } catch (error) {
    return res.status(503).json({ error: error.message });
  }

  const shop = await Shop.findOne({ ownerId: user._id });
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  const restrictionError = sellerRestrictionError(shop);
  if (restrictionError) return res.status(403).json({ error: restrictionError });
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
  const paymentMethod = req.body?.paymentMethod;
  if (!['card', 'wallet'].includes(paymentMethod)) {
    return res.status(400).json({ error: 'Choose card or Z balance for the assistant purchase.' });
  }

  const shopSnapshot = await Shop.findOne({ ownerId: user._id });
  if (!shopSnapshot) return res.status(404).json({ error: 'Shop not found.' });
  const restrictionError = sellerRestrictionError(shopSnapshot);
  if (restrictionError) return res.status(403).json({ error: restrictionError });
  if (isAssistantPlanPaid(shopSnapshot)) {
    return res.json({
      shop: {
        assistantPlanActive: shopSnapshot.assistantPlanActive,
        assistantPlanPaidAt: shopSnapshot.assistantPlanPaidAt,
        assistantEnabled: shopSnapshot.assistantEnabled
      },
      assistantServiceConfigured: await isAssistantModelReady(),
      message: 'The shop assistant add-on is already active. You were not charged again.'
    });
  }

  const { walletUsedNAD, cardDueNAD } = calculateWalletPayment(assistantPriceNAD, user.walletBalanceNAD, paymentMethod);
  if (paymentMethod === 'wallet' && walletUsedNAD <= 0) {
    return res.status(409).json({ error: 'Your Z balance is empty. Choose card payment instead.' });
  }
  const paymentIntent = cardDueNAD > 0 ? paymentAdapter.createIntent(`ASSISTANT-${shopSnapshot._id}`) : null;
  const payment = paymentIntent
    ? paymentAdapter.confirmIntent(paymentIntent.reference)
    : { status: 'paid', confirmedAt: new Date() };
  if (payment.status !== 'paid') return res.status(402).json({ error: 'Assistant payment was not completed.' });

  const purchase = await withMongoTransaction(async (session) => {
    const currentShop = await Shop.findOne({
      _id: shopSnapshot._id,
      ownerId: user._id
    }).session(session);
    if (!currentShop) throw apiError(404, 'Shop not found.');
    if (isAssistantPlanPaid(currentShop)) return { shop: currentShop, alreadyPaid: true };

    if (walletUsedNAD > 0) {
      await applyWalletTransaction({
        userId: user._id,
        reference: `assistant:${currentShop._id}`,
        type: 'purchase_debit',
        amountNAD: walletUsedNAD,
        orderNumber: `AI-${currentShop._id}`,
        description: 'Shop AI assistant add-on',
        session,
        insufficientBalanceMessage: 'Your Z balance changed. Refresh and choose a payment method.'
      });
    }

    currentShop.assistantPlanActive = true;
    currentShop.assistantPlanPaidAt = payment.confirmedAt || new Date();
    await currentShop.save({ session });
    return { shop: currentShop, alreadyPaid: false };
  });
  const { shop } = purchase;
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  if (purchase.alreadyPaid) {
    return res.json({
      shop: {
        assistantPlanActive: shop.assistantPlanActive,
        assistantPlanPaidAt: shop.assistantPlanPaidAt,
        assistantEnabled: shop.assistantEnabled
      },
      assistantServiceConfigured: await isAssistantModelReady(),
      message: 'The shop assistant add-on is already active. You were not charged again.'
    });
  }
  return res.json({
    shop: {
      assistantPlanActive: shop.assistantPlanActive,
      assistantPlanPaidAt: shop.assistantPlanPaidAt,
      assistantEnabled: shop.assistantEnabled
    },
    assistantServiceConfigured: await isAssistantModelReady(),
    simulated: true,
    message: walletUsedNAD > 0 && cardDueNAD > 0
      ? `N$ ${walletUsedNAD.toFixed(2)} deducted from your Z balance and N$ ${cardDueNAD.toFixed(2)} simulated on a test card. The one-time assistant add-on is active.`
      : walletUsedNAD > 0
        ? `N$ ${walletUsedNAD.toFixed(2)} deducted from your Z balance. The one-time assistant add-on is active.`
        : `N$ ${cardDueNAD.toFixed(2)} simulated on a test card; no real payment was processed. The one-time assistant add-on is active.`
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

  const shop = await Shop.findOneAndUpdate({ ownerId: user._id }, { $set: { shippingRates, autoApprovalEnabled } }, { returnDocument: 'after', runValidators: true });
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
  const restrictionError = sellerRestrictionError(shop);
  if (restrictionError) return res.status(403).json({ error: restrictionError });
  if (assistantEnabled && !isAssistantPlanPaid(shop)) {
    return res.status(402).json({ error: 'Purchase the shop assistant add-on before turning it on.' });
  }

  shop.assistantEnabled = assistantEnabled;
  await shop.save();
  return res.json({
    assistantEnabled: shop.assistantEnabled,
    assistantPlanActive: shop.assistantPlanActive,
    assistantPlanPaidAt: shop.assistantPlanPaidAt,
    assistantServiceConfigured: await isAssistantModelReady()
  });
});

app.post('/api/seller/shop', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to create a shop.' });

  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const description = typeof req.body?.description === 'string' ? req.body.description.trim() : '';
  const town = req.body?.town;
  const nameKey = name ? normalizeDuplicateText(name) : '';
  if (!name || name.length > 80 || !nameKey || !description || description.length > 500 || !namibianTowns.includes(town)) {
    return res.status(400).json({ error: 'Enter a shop name, a short description, and a valid town.' });
  }
  if (await findDuplicateShopName(nameKey)) {
    return res.status(409).json({ error: 'A shop with the same name already exists.' });
  }

  const slug = `${name.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50) || 'shop'}-${randomBytes(3).toString('hex')}`;
  try {
    const shop = await Shop.create({ ownerId: user._id, name, nameKey, description, town, slug, approvalStatus: 'pending' });
    return res.status(201).json({ shop: { id: shop._id.toString(), name: shop.name, description: shop.description, town: shop.town, slug: shop.slug, approvalStatus: shop.approvalStatus } });
  } catch (error) {
    if (error.code === 11000 && error.keyPattern?.ownerId) {
      return res.status(409).json({ error: 'You already have a shop. Refresh this page to manage it.' });
    }
    if (error.code === 11000 && error.keyPattern?.nameKey) {
      return res.status(409).json({ error: 'A shop with the same name already exists.' });
    }
    throw error;
  }
});

app.post('/api/seller/products/upload', sellerUploadRateLimit, async (req, res, next) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to upload product images.' });
  const shop = await Shop.findOne({ ownerId: user._id })
    .select('_id sellerSuspended sellerRestrictionStatus sellerRestrictedUntil');
  if (!shop) return res.status(409).json({ error: 'Create your storefront before uploading product images.' });
  const restrictionError = sellerRestrictionError(shop);
  if (restrictionError) return res.status(403).json({ error: restrictionError });
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

  const shop = await Shop.findOneAndUpdate({ ownerId: user._id }, { $set: { coverImageUrl } }, { returnDocument: 'after', runValidators: true });
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  return res.json({ coverImageUrl: shop.coverImageUrl });
});

app.get('/api/seller/products', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to manage listings.' });
  const cancelledUnpaidPromotions = await reconcileUnpaidPromotions(user._id);
  const shop = await Shop.findOne({ ownerId: user._id });
  if (!shop) return res.json({ products: [], cancelledUnpaidPromotions });
  const now = new Date();
  await PromotionCampaign.updateMany(
    { shopId: shop._id, status: 'active', expiresAt: { $lte: now } },
    { $set: { status: 'expired' } }
  );
  const products = await Product.find({ shopId: shop._id }).sort({ createdAt: -1 }).lean();
  const campaigns = await PromotionCampaign.find({
    shopId: shop._id,
    status: { $in: ['active', 'pending'] }
  }).sort({ createdAt: -1 }).lean();
  const campaignsByProduct = new Map();
  campaigns.forEach((campaign) => {
    if (!campaignsByProduct.has(campaign.productId.toString())) campaignsByProduct.set(campaign.productId.toString(), campaign);
  });
  return res.json({ products: products.map((product) => {
    const campaign = campaignsByProduct.get(product._id.toString());
    return {
      ...product,
      id: product._id.toString(),
      promotion: campaign ? {
        id: campaign._id.toString(),
        status: campaign.status,
        amountNAD: campaign.amountNAD,
        startsAt: campaign.startsAt,
        expiresAt: campaign.expiresAt,
        paymentExpiresAt: campaign.paymentExpiresAt
      } : null
    };
  }), cancelledUnpaidPromotions });
});

app.post('/api/seller/products/:id/promotions', promotionWriteRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to promote a listing.' });
  if (!mockPaymentsEnabled) return res.status(503).json({ error: 'Promotion payments are unavailable until a live payment provider is configured.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Listing not found.' });

  const shop = await Shop.findOne({ ownerId: user._id });
  if (!shop) return res.status(404).json({ error: 'Shop not found.' });
  const restrictionError = sellerRestrictionError(shop);
  if (restrictionError) return res.status(403).json({ error: restrictionError });
  if (shop.approvalStatus === 'pending' || shop.approvalStatus === 'rejected') {
    return res.status(409).json({ error: 'Your shop must be approved before promoting listings.' });
  }
  const product = await Product.findOne({
    _id: req.params.id,
    shopId: shop._id,
    status: 'active',
    isAvailable: true,
    stock: { $gt: 0 },
    reviewStatus: { $in: ['approved', null] },
    moderationStatus: { $ne: 'hidden' }
  });
  if (!product) return res.status(404).json({ error: 'Only active, in-stock listings can be promoted.' });

  const now = new Date();
  await PromotionCampaign.updateMany(
    { productId: product._id, status: 'active', expiresAt: { $lte: now } },
    { $set: { status: 'expired' } }
  );
  await PromotionCampaign.updateMany(
    { productId: product._id, status: 'pending', paymentExpiresAt: { $lte: now } },
    { $set: { status: 'cancelled' } }
  );
  const existingCampaign = await PromotionCampaign.findOne({
    productId: product._id,
    status: { $in: ['active', 'pending'] }
  });
  if (existingCampaign) {
    return res.status(409).json({
      error: existingCampaign.status === 'active'
        ? 'This product already has an active promotion.'
        : 'A promotion payment is already pending for this product.'
    });
  }

  const campaignId = new mongoose.Types.ObjectId();
  const paymentIntent = paymentAdapter.createIntent(`PROMO-${campaignId.toString()}`);
  const campaign = await PromotionCampaign.create({
    _id: campaignId,
    productId: product._id,
    sellerId: user._id,
    shopId: shop._id,
    amountNAD: promotionPriceNAD,
    durationDays: promotionDurationDays,
    paymentReference: paymentIntent.reference,
    paymentExpiresAt: new Date(now.getTime() + 15 * 60 * 1000)
  });
  return res.status(201).json({
    promotion: {
      id: campaign._id.toString(),
      status: campaign.status,
      amountNAD: campaign.amountNAD,
      durationDays: campaign.durationDays,
      paymentExpiresAt: campaign.paymentExpiresAt,
      mock: true,
      message: 'Test payment only. No money will be charged.'
    }
  });
});

app.post('/api/seller/promotions/:id/simulate-payment', promotionWriteRateLimit, async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to complete promotion payment.' });
  if (!mockPaymentsEnabled) return res.status(503).json({ error: 'Promotion payments are unavailable until a live payment provider is configured.' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Promotion not found.' });
  const paymentMethod = req.body?.paymentMethod;
  if (!['card', 'wallet'].includes(paymentMethod)) {
    return res.status(400).json({ error: 'Choose card or Z balance for the promotion payment.' });
  }

  const now = new Date();
  const campaign = await PromotionCampaign.findOne({
    _id: req.params.id,
    sellerId: user._id,
    status: 'pending',
    paymentExpiresAt: { $gt: now }
  });
  if (!campaign) return res.status(404).json({ error: 'Pending promotion payment not found or expired.' });
  const campaignShop = await Shop.findById(campaign.shopId)
    .select('sellerSuspended sellerRestrictionStatus sellerRestrictedUntil').lean();
  const restrictionError = sellerRestrictionError(campaignShop);
  if (restrictionError) return res.status(403).json({ error: restrictionError });
  const product = await Product.findOne({
    _id: campaign.productId,
    shopId: campaign.shopId,
    status: 'active',
    isAvailable: true,
    stock: { $gt: 0 },
    reviewStatus: { $in: ['approved', null] },
    moderationStatus: { $ne: 'hidden' }
  });
  if (!product) {
    campaign.status = 'cancelled';
    await campaign.save();
    return res.status(409).json({ error: 'This listing is no longer eligible for promotion.' });
  }

  const { walletUsedNAD, cardDueNAD } = calculateWalletPayment(campaign.amountNAD, user.walletBalanceNAD, paymentMethod);
  if (paymentMethod === 'wallet' && walletUsedNAD <= 0) {
    return res.status(409).json({ error: 'Your Z balance is empty. Choose card payment instead.' });
  }
  const payment = cardDueNAD > 0 ? paymentAdapter.confirmIntent(campaign.paymentReference) : { status: 'paid', confirmedAt: now };
  if (payment.status !== 'paid') return res.status(402).json({ error: 'Promotion payment was not completed.' });
  const schedule = buildPromotionSchedule(payment.confirmedAt || now);
  try {
    const activated = await withMongoTransaction(async (session) => {
      if (walletUsedNAD > 0) {
        await applyWalletTransaction({
          userId: user._id,
          reference: `promotion:${campaign._id}`,
          type: 'purchase_debit',
          amountNAD: walletUsedNAD,
          orderNumber: `PROMO-${campaign._id}`,
          description: `Promotion for ${product.title}`,
          session,
          insufficientBalanceMessage: 'Your Z balance changed. Refresh and choose a payment method.'
        });
      }
      const promotion = await PromotionCampaign.findOneAndUpdate({
        _id: campaign._id,
        sellerId: user._id,
        status: 'pending',
        paymentExpiresAt: { $gt: now }
      }, {
        $set: {
          status: 'active',
          paymentMethod,
          walletUsedNAD,
          cardDueNAD,
          paidAt: schedule.startsAt,
          startsAt: schedule.startsAt,
          expiresAt: schedule.expiresAt
        }
      }, { returnDocument: 'after', runValidators: true, session });
      if (!promotion) throw apiError(409, 'This promotion payment is no longer pending.');
      return promotion;
    });
    return res.json({
      promotion: {
        id: activated._id.toString(),
        productId: activated.productId.toString(),
        status: activated.status,
        amountNAD: activated.amountNAD,
        paymentMethod: activated.paymentMethod,
        walletUsedNAD: activated.walletUsedNAD,
        cardDueNAD: activated.cardDueNAD,
        startsAt: activated.startsAt,
        expiresAt: activated.expiresAt
      },
      mock: true,
      message: walletUsedNAD > 0 && cardDueNAD > 0
        ? `N$ ${walletUsedNAD.toFixed(2)} deducted from your Z balance and N$ ${cardDueNAD.toFixed(2)} simulated on a test card. Promotion is live for 7 days.`
        : walletUsedNAD > 0
          ? `N$ ${walletUsedNAD.toFixed(2)} deducted from your Z balance. Promotion is live for 7 days.`
          : `N$ ${cardDueNAD.toFixed(2)} simulated on a test card; no real payment was processed. Promotion is live for 7 days.`
    });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'This product already has an active promotion.' });
    throw error;
  }
});

function normalizeProductListingInput(input) {
  const title = typeof input?.title === 'string' ? input.title.trim() : '';
  const description = typeof input?.description === 'string' ? input.description.trim() : '';
  const category = typeof input?.category === 'string' ? input.category.trim() : '';
  const rawPriceNAD = Number(input?.priceNAD);
  const rawStock = Number(input?.stock);
  const imageUrls = normalizeImageUrls(input?.imageUrls || input?.imageUrl || []);
  if (title.length > 100 || description.length > 1500 || category.length > 100) {
    return { error: 'Product title, description, or category is too long.' };
  }
  if ((Number.isFinite(rawPriceNAD) && rawPriceNAD > 10000000)
    || (Number.isFinite(rawStock) && rawStock > 100000)
    || (Number.isFinite(rawStock) && !Number.isInteger(rawStock))) {
    return { error: 'Price or stock is outside the supported range.' };
  }
  if (!imageUrls.every((url) => validateImageUrl(url))) {
    return { error: 'Product images must use valid HTTPS image URLs.' };
  }
  return {
    title,
    description,
    category,
    priceNAD: Number.isFinite(rawPriceNAD) && rawPriceNAD >= 0.01 && rawPriceNAD <= 10000000 ? rawPriceNAD : 0,
    stock: Number.isInteger(rawStock) && rawStock > 0 && rawStock <= 100000 ? rawStock : 0,
    imageUrls,
    imageUrl: imageUrls[0] || ''
  };
}

function getListingReviewDecision({ shop, seller, product }) {
  return getProductReviewDecision({
    product,
    sellerEmailVerified: Boolean(seller.emailVerified),
    sellerAccountSuspicious: Boolean(
      seller.isSuspended
      || shop.sellerSuspended
      || shop.sellerRestrictionStatus === 'banned'
      || isSellerAutoRestricted(shop)
    )
  });
}

app.post('/api/seller/products', async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to publish a listing.' });
  const shop = await Shop.findOne({ ownerId: user._id });
  if (!shop) return res.status(409).json({ error: 'Create your storefront before adding products.' });
  const restrictionError = sellerRestrictionError(shop);
  if (restrictionError) return res.status(403).json({ error: restrictionError });

  const listing = normalizeProductListingInput(req.body);
  if (listing.error) return res.status(400).json({ error: listing.error });
  const duplicateKey = buildProductDuplicateKey(listing);
  if (await findDuplicateProduct(shop._id, duplicateKey)) {
    return res.status(409).json({ error: 'A matching product listing already exists in your shop.' });
  }

  const reviewDecision = getListingReviewDecision({ shop, seller: user, product: listing });
  let product;
  try {
    product = await Product.create({
      shopId: shop._id,
      duplicateKey,
      ...listing,
      isAvailable: listing.stock > 0,
      town: shop.town,
      reviewStatus: reviewDecision.reviewStatus,
      reviewReasons: reviewDecision.reviewReasons
    });
  } catch (error) {
    if (error.code === 11000 && error.keyPattern?.duplicateKey) {
      return res.status(409).json({ error: 'A matching product listing already exists in your shop.' });
    }
    throw error;
  }
  const notificationError = await notifyProductReviewDecision({ product, shop, seller: user, reviewDecision });
  return res.status(201).json({
    product: {
      id: product._id.toString(),
      title: product.title,
      priceNAD: product.priceNAD,
      stock: product.stock,
      category: product.category,
      reviewStatus: product.reviewStatus,
      reviewReasons: product.reviewReasons
    },
    notificationError
  });
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
  let reviewDecision = null;
  if (req.body?.status !== undefined) {
    if (!['active', 'archived'].includes(req.body.status)) return res.status(400).json({ error: 'Invalid listing status.' });
    updates = { status: req.body.status };
  } else {
    const listing = normalizeProductListingInput(req.body);
    if (listing.error) return res.status(400).json({ error: listing.error });
    const duplicateKey = buildProductDuplicateKey(listing);
    if (await findDuplicateProduct(shop._id, duplicateKey, product._id)) {
      return res.status(409).json({ error: 'A matching product listing already exists in your shop.' });
    }

    reviewDecision = getListingReviewDecision({ shop, seller: user, product: listing });
    updates = {
      duplicateKey,
      ...listing,
      isAvailable: listing.stock > 0,
      reviewStatus: reviewDecision.reviewStatus,
      reviewReasons: reviewDecision.reviewReasons
    };
  }

  let updated;
  try {
    updated = await Product.findByIdAndUpdate(product._id, { $set: updates }, { returnDocument: 'after', runValidators: true }).lean();
  } catch (error) {
    if (error.code === 11000 && error.keyPattern?.duplicateKey) {
      return res.status(409).json({ error: 'A matching product listing already exists in your shop.' });
    }
    throw error;
  }
  let notificationError = null;
  if (reviewDecision) {
    notificationError = await notifyProductReviewDecision({
      product: updated,
      shop,
      seller: user,
      reviewDecision
    });
  }
  return res.json({
    product: {
      id: updated._id.toString(),
      title: updated.title,
      description: updated.description,
      priceNAD: updated.priceNAD,
      stock: updated.stock,
      category: updated.category,
      imageUrl: updated.imageUrl,
      imageUrls: updated.imageUrls || [],
      status: updated.status,
      reviewStatus: updated.reviewStatus,
      reviewReasons: updated.reviewReasons || []
    },
    notificationError
  });
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
  if (await getSessionUser(req)) return res.redirect(getSafeReturnPath(req.query.returnTo));
  return res.sendFile(path.join(__dirname, '..', 'client', 'home.html'));
});

app.get('/reset-password', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'reset-password.html'));
});

app.get('/verify-email', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'client', 'verify-email.html'));
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
  await Promise.all([User.init(), Session.init(), PasswordReset.init(), Shop.init(), Product.init(), PromotionCampaign.init(), PromotionEngagement.init(), Order.init(), WalletTransaction.init(), WalletReconciliationAlert.init(), ListingReport.init(), ListingThresholdEvent.init(), ModerationAudit.init(), SupportRequest.init(), SupportNotification.init(), SellerNotification.init(), AccountNotification.init(), SuspensionAppeal.init(), SuspensionAppealAccess.init(), PlatformSetting.init(), LoginWallpaper.init()]);
  const reservationSweep = setInterval(() => {
    releaseExpiredReservations().catch((error) => console.error('Reservation cleanup failed:', error.message));
  }, 60 * 1000);
  reservationSweep.unref();
  await advancePayoutLifecycle();
  const payoutSweep = setInterval(() => {
    advancePayoutLifecycle().catch((error) => console.error('Seller wallet credit sweep failed:', error.message));
  }, payoutSweepIntervalMs);
  payoutSweep.unref();
  await processAutomaticSellerRestrictions();
  const sellerRestrictionSweep = setInterval(() => {
    processAutomaticSellerRestrictions().catch((error) => console.error('Automatic seller restriction sweep failed:', error.message));
  }, 60 * 1000);
  sellerRestrictionSweep.unref();

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
  normalizeCartItems,
  normalizeSavedCartItems,
  normalizeSavedWishlistIds,
  buildPromotionSchedule,
  normalizePromotionVisitorId,
  calculatePromotionClickThroughRate,
  getBuyerDisplayName,
  normalizeDuplicateText,
  buildProductDuplicateKey,
  buildSellerMarketBenchmarks,
  normalizeSupportRequest,
  normalizeSuspensionAppeal,
  normalizeSuspensionAppealStatusEmail,
  normalizeSuspensionAppealStatusAccess,
  normalizeSuspensionAppealReview,
  getSupportTriage,
  getSupportRequestVisibilityFilter,
  getSupportCategory,
  getListingReportCredibilityPoints,
  isListingReportBlocked,
  shouldAutoHideListing,
  shouldRestoreReportHiddenListing,
  shouldAutoRestrictSeller,
  isSellerAutoRestricted,
  normalizePasswordResetInput,
  resolveAppBaseUrl,
  describeLoginDevice,
  getSafeReturnPath,
  normalizeProfileInput,
  isValidEmailVerificationToken,
  isEmailVerified,
  isConfiguredAdminIdentity,
  isAdminUser,
  isModeratorUser,
  isSandboxUser,
  isLocalMongoUri,
  getPublicRole,
  isValidCommissionRatePercent,
  validateImageUrl,
  hasValidImageSignature,
  resolvePayoutStatus,
  calculateWalletPayment,
  reconcileWalletBalance,
  isMatchingPromotionWalletDebit,
  getPromotionPaymentIssue,
  shouldCancelUnpaidPromotion,
  normalizeAdminNotificationInput,
  isAssistantPlanPaid,
  assertProductionPaymentConfiguration,
  assertProductionAdminConfiguration
};