const restrictedProductSignals = [
  {
    reason: 'Medicines and controlled drugs cannot be listed. Remove the restricted product or contact support if this is a false match.',
    terms: [
      /\bpills?\b/i,
      /\bdrugs?\b/i,
      /\bmedications?\b/i,
      /\bmedicines?\b/i,
      /\bsupplements?\b/i,
      /\bprescription\b/i,
      /\bcontrolled\s+substances?\b/i,
      /\bnarcotics?\b/i,
      /\bpharmaceuticals?\b/i,
      /\banabolic\s+steroids?\b/i,
      /\bantibiotics?\b/i,
      /\bpain\s?killers?\b/i,
      /\bcbd\b/i,
      /\bcannabis\b/i,
      /\bmarijuana\b/i,
      /\bhash(?:ish)?\b/i,
      /\bcocaine\b/i,
      /\bheroin\b/i,
      /\bmeth(?:amphetamine)?\b/i,
      /\bmandrax\b/i,
      /\becstasy\b/i,
      /\bfentanyl\b/i,
      /\bopioids?\b/i
    ]
  },
  {
    reason: 'Weapons, firearms, ammunition, and explosives cannot be listed. Remove the restricted product or contact support if this is a false match.',
    terms: [
      /\bweapons?\b/i,
      /\bfirearms?\b/i,
      /\bhandguns?\b/i,
      /\brifles?\b/i,
      /\bshotguns?\b/i,
      /\bammunition\b/i,
      /\bammo\b/i,
      /\bexplosives?\b/i,
      /\bfireworks?\b/i,
      /\bgrenades?\b/i,
      /\bbombs?\b/i,
      /\bstun\s?guns?\b/i,
      /\btasers?\b/i,
      /\bbrass\s+knuckles\b/i,
      /\bpepper\s+spray\b/i
    ]
  },
  {
    reason: 'Counterfeit or stolen goods cannot be listed. Remove the restricted product or contact support if this is a false match.',
    terms: [
      /\bcounterfeit\b/i,
      /\bknock[\s-]?offs?\b/i,
      /\bfake\s+(?:brand|designer|label|logo|goods?)\b/i,
      /\bstolen\s+(?:goods?|property|item|vehicle|phone|device)\b/i,
      /\b(?:goods?|property|item|vehicle|phone|device)\s+(?:is|are)\s+stolen\b/i
    ]
  },
  {
    reason: 'Products made from protected wildlife cannot be listed. Remove the restricted product or contact support if this is a false match.',
    terms: [
      /\bivory\b/i,
      /\brhino(?:ceros)?\s+horn\b/i,
      /\bpangolin\s+(?:scales?|products?)\b/i,
      /\belephant\s+tusks?\b/i,
      /\bprotected\s+(?:wildlife|species|animal)\b/i,
      /\bcites\s+(?:permit|listed|species)\b/i
    ]
  },
  {
    reason: 'This product may require an import or agricultural permit and cannot be listed without verification. Contact support if you have the required permit.',
    terms: [
      /\bhoney\b/i,
      /\blive\s+(?:animals?|plants?)\b/i,
      /\b(?:raw|fresh)\s+meat\b/i,
      /\bmeat\s+offal\b/i,
      /\b(?:wheat|maize|corn|cereal)\b/i,
      /\braw\s+hides?\b/i,
      /\b(?:animal|raw)\s+skins?\b/i,
      /\bused\s+(?:pneumatic\s+)?tyres?\b/i,
      /\b(?:rough|uncut)\s+diamonds?\b/i,
      /\b(?:raw|unrefined)\s+gold\b/i
    ]
  },
  {
    reason: 'Alcohol, tobacco, and nicotine products cannot be listed. Remove the restricted product or contact support if this is a false match.',
    terms: [
      /\balcohol\b/i,
      /\bliquor\b/i,
      /\bspirits\b/i,
      /\b(?:beer|wine|vodka|whisk(?:e)?y|rum|gin|brandy)\b/i,
      /\btobacco\b/i,
      /\bcigarettes?\b/i,
      /\bcigars?\b/i,
      /\be[\s-]?cigarettes?\b/i,
      /\bvapes?\b/i,
      /\bnicotine\b/i
    ]
  },
  {
    reason: 'Recalled or unsafe products cannot be listed. Remove the restricted product or contact support if this is a false match.',
    terms: [
      /\brecalled\s+(?:product|item|toy|device|medicine)\b/i,
      /\bproduct\s+recall\b/i,
      /\bunsafe\s+(?:product|toy|device|medicine)\b/i
    ]
  },
  {
    reason: 'Telecommunications equipment may require CRAN type approval and cannot be published without verification. Contact support if you have approval.',
    terms: [
      /\bwi[\s-]?fi\b/i,
      /\bbluetooth\b/i,
      /\b(?:wifi|wireless)\s+(?:router|modem|transmitter)\b/i,
      /\b(?:radio|network)\s+(?:transmitter|equipment)\b/i
    ]
  },
  {
    reason: 'Second-hand clothing cannot be listed. Remove the restricted product or contact support if this is a false match.',
    terms: [
      /\bsecond[\s-]hand\s+(?:clothes?|clothing)\b/i,
      /\bused\s+(?:clothes?|clothing)\b/i
    ]
  }
];

function getProductBasicDataIssues(product = {}) {
  const safeProduct = (product && typeof product === 'object') ? product : {};
  const reasons = [];
  const title = typeof safeProduct.title === 'string' ? safeProduct.title.trim() : '';
  const description = typeof safeProduct.description === 'string' ? safeProduct.description.trim() : '';
  const category = typeof safeProduct.category === 'string' ? safeProduct.category.trim() : '';
  const imageUrls = Array.isArray(safeProduct.imageUrls) ? safeProduct.imageUrls : [];
  const images = [...imageUrls, safeProduct.imageUrl];
  const priceNAD = Number(safeProduct.priceNAD);
  const stock = Number(safeProduct.stock);

  if (!title) reasons.push('Product title is missing.');
  if (!description) reasons.push('Product description is missing.');
  if (!category) reasons.push('Product category is missing.');
  if (!images.some((url) => typeof url === 'string' && url.trim())) reasons.push('At least one product image is required.');
  if (!Number.isFinite(priceNAD) || priceNAD <= 0) reasons.push('Price must be greater than N$ 0.00.');
  if (!Number.isInteger(stock) || stock <= 0) reasons.push('Stock must be greater than zero.');
  return [...new Set(reasons)];
}

function getRestrictedCategoryReason(category) {
  if (typeof category !== 'string') return null;
  const normalizedCategory = category.toLocaleLowerCase();
  if (/\bhealth\b|\bmedicine\b|\bmedicines\b|\bmedical\b|\bpharma(?:cy|ceutical)?\b/.test(normalizedCategory)) {
    return 'Health and medicine products cannot be listed. Contact support if this is a false match.';
  }
  if (/\btelecom(?:munications?)?\b|\bwi[\s-]?fi\b|\bbluetooth\b/.test(normalizedCategory)) {
    return 'Telecom, Wi-Fi, and Bluetooth products may require CRAN type approval and cannot be published without verification. Contact support if you have approval.';
  }
  if (/\bfood\b|\bagriculture\b|\bagricultural\b/.test(normalizedCategory)) {
    return 'Food and agriculture products may require permits and cannot be published without verification. Contact support if you have the required permits.';
  }
  if (/\bsecond[\s-]hand\b|\bused\s+(?:clothes?|clothing)\b/.test(normalizedCategory)) {
    return 'Second-hand clothing cannot be listed. Contact support if this is a false match.';
  }
  return null;
}

function getProductReviewDecision(options = {}) {
  const safeOptions = (options && typeof options === 'object') ? options : {};
  const {
    product = {},
    sellerEmailVerified = false,
    sellerAccountSuspicious = false
  } = safeOptions;
  const safeProduct = (product && typeof product === 'object') ? product : {};
  const reasons = getProductBasicDataIssues(safeProduct);
  const category = typeof safeProduct.category === 'string' ? safeProduct.category.trim() : '';

  if (!sellerEmailVerified) reasons.push('Seller account email is not verified.');
  if (sellerAccountSuspicious) reasons.push('Seller account has an active suspension or restriction.');
  const categoryReason = getRestrictedCategoryReason(category);
  if (categoryReason) reasons.push(categoryReason);

  const searchableText = `${safeProduct.title || ''}\n${safeProduct.description || ''}\n${category}`;
  restrictedProductSignals.forEach((signal) => {
    if (signal.terms.some((term) => term.test(searchableText))) reasons.push(signal.reason);
  });

  const uniqueReasons = [...new Set(reasons)];

  return {
    reviewStatus: uniqueReasons.length ? 'rejected' : 'approved',
    reviewReasons: uniqueReasons
  };
}

module.exports = { getProductBasicDataIssues, getProductReviewDecision };
