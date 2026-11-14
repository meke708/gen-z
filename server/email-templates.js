function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

function getHttpsUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.toString() : '';
  } catch {
    return '';
  }
}

function createVerificationEmail({ name, verificationUrl, featuredProduct = null }) {
  const safeName = escapeHtml(name || 'there');
  const safeUrl = escapeHtml(verificationUrl);
  const greetingName = name || 'there';
  const productUrl = getHttpsUrl(featuredProduct?.url);
  const imageUrl = getHttpsUrl(featuredProduct?.imageUrl);
  const productTitle = featuredProduct?.title ? escapeHtml(featuredProduct.title) : '';
  const shopName = featuredProduct?.shopName ? escapeHtml(featuredProduct.shopName) : '';
  const town = featuredProduct?.town ? escapeHtml(featuredProduct.town) : '';
  const price = Number(featuredProduct?.priceNAD);
  const priceLabel = Number.isFinite(price) ? `N$ ${price.toFixed(2)}` : '';
  const featuredProductText = productUrl && productTitle
    ? `\n\nSponsored find from the Z marketplace:\n${featuredProduct.title}${shopName ? ` by ${featuredProduct.shopName}` : ''}${priceLabel ? ` · ${priceLabel}` : ''}\n${productUrl}`
    : '';
  const featuredProductHtml = productUrl && productTitle
    ? `<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:30px;border:1px solid #dfe8df;border-radius:10px;overflow:hidden;">
      <tr>
        <td colspan="2" style="padding:14px 18px;background:#f2f7e9;color:#18382e;font-size:12px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;">A promoted find from the Z marketplace</td>
      </tr>
      ${imageUrl ? `<tr><td colspan="2" style="padding:0;"><a href="${escapeHtml(productUrl)}" style="text-decoration:none;"><img src="${escapeHtml(imageUrl)}" alt="${productTitle}" width="536" style="display:block;width:100%;max-width:536px;height:auto;border:0;"></a></td></tr>` : ''}
      <tr>
        <td colspan="2" style="padding:18px 20px 20px;">
          <p style="margin:0 0 6px;color:#52705e;font-size:12px;font-weight:bold;">${shopName}${shopName && town ? ' · ' : ''}${town}</p>
          <h2 style="margin:0 0 10px;color:#18382e;font-size:20px;line-height:1.35;word-break:break-word;">${productTitle}</h2>
          ${priceLabel ? `<p style="margin:0 0 16px;color:#18382e;font-size:18px;font-weight:bold;">${priceLabel}</p>` : ''}
          <a href="${escapeHtml(productUrl)}" style="display:inline-block;padding:11px 18px;border-radius:6px;background:#18382e;color:#d8f36a;font-size:14px;font-weight:bold;text-decoration:none;">View this listing</a>
        </td>
      </tr>
    </table>`
    : '';

  return {
    text: `Hello ${greetingName},\n\nThank you for registering with Z Namibia. Verify your email address within 24 hours:\n${verificationUrl}${featuredProductText}\n\nIf you did not create this account, you can ignore this email.`,
    html: `<!doctype html>
<html lang="en">
  <body style="margin:0;padding:24px;background:#f2f5ef;font-family:Arial,Helvetica,sans-serif;color:#24352c;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;margin:0 auto;background:#ffffff;border:1px solid #dfe8df;border-radius:12px;">
      <tr>
        <td style="padding:24px 30px;background:#18382e;border-radius:12px 12px 0 0;color:#ffffff;">
          <table role="presentation" cellspacing="0" cellpadding="0">
            <tr>
              <td width="48" height="48" align="center" valign="middle" style="width:48px;height:48px;border-radius:50%;background:#18382e;border:2px solid #d8f36a;color:#d8f36a;font-family:Georgia,'Times New Roman',serif;font-size:38px;font-style:italic;font-weight:bold;line-height:44px;">Z</td>
              <td style="padding-left:12px;">
                <div style="font-size:18px;font-weight:bold;letter-spacing:1px;">Z NAMIBIA</div>
                <div style="margin-top:4px;font-size:13px;color:#d8f36a;">Your local marketplace</div>
              </td>
            </tr>
          </table>
        </td>
      </tr>
      <tr>
        <td style="padding:30px;">
          <h1 style="margin:0 0 14px;font-size:25px;line-height:1.3;color:#18382e;">Thanks for registering, ${safeName}!</h1>
          <p style="margin:0 0 22px;font-size:16px;line-height:1.6;color:#526257;">We're glad you're here. Verify your email to finish setting up your account and start exploring local shops.</p>
          <p style="margin:0 0 24px;">
            <a href="${safeUrl}" style="display:inline-block;padding:13px 22px;border-radius:6px;background:#d8f36a;color:#18382e;font-size:15px;font-weight:bold;text-decoration:none;">Verify email address</a>
          </p>
          ${featuredProductHtml}
          <p style="margin:24px 0 8px;font-size:14px;line-height:1.6;color:#526257;">This verification link expires in 24 hours.</p>
          <p style="margin:0 0 8px;font-size:13px;line-height:1.6;color:#68776c;">If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="margin:0;word-break:break-all;font-size:13px;line-height:1.6;"><a href="${safeUrl}" style="color:#315c42;">${safeUrl}</a></p>
        </td>
      </tr>
      <tr>
        <td style="padding:18px 30px;border-top:1px solid #e6ece4;font-size:12px;line-height:1.6;color:#68776c;">
          If you didn't create a Z Namibia account, you can safely ignore this email.
        </td>
      </tr>
    </table>
  </body>
</html>`
  };
}

module.exports = { createVerificationEmail };
