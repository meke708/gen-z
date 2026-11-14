function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

function createVerificationEmail({ name, verificationUrl }) {
  const safeName = escapeHtml(name || 'there');
  const safeUrl = escapeHtml(verificationUrl);
  const greetingName = name || 'there';

  return {
    text: `Hello ${greetingName},\n\nThank you for registering with Z Namibia. Verify your email address within 24 hours:\n${verificationUrl}\n\nIf you did not create this account, you can ignore this email.`,
    html: `<!doctype html>
<html lang="en">
  <body style="margin:0;padding:24px;background:#f3f6fb;font-family:Arial,Helvetica,sans-serif;color:#17233c;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;margin:0 auto;background:#ffffff;border:1px solid #e1e7f0;border-radius:12px;">
      <tr>
        <td style="padding:28px 32px;background:#102653;border-radius:12px 12px 0 0;color:#ffffff;">
          <div style="font-size:13px;font-weight:bold;letter-spacing:2px;">Z NAMIBIA</div>
          <div style="margin-top:8px;font-size:14px;color:#dbe5f6;">Welcome to the community</div>
        </td>
      </tr>
      <tr>
        <td style="padding:32px;">
          <h1 style="margin:0 0 16px;font-size:25px;line-height:1.3;color:#17233c;">Thanks for registering, ${safeName}!</h1>
          <p style="margin:0 0 22px;font-size:16px;line-height:1.6;color:#4c5870;">We're glad you're here. Please verify your email address to finish setting up your account.</p>
          <p style="margin:0 0 24px;">
            <a href="${safeUrl}" style="display:inline-block;padding:13px 22px;border-radius:7px;background:#e8a526;color:#17233c;font-size:15px;font-weight:bold;text-decoration:none;">Verify email address</a>
          </p>
          <p style="margin:0 0 8px;font-size:14px;line-height:1.6;color:#4c5870;">This link expires in 24 hours.</p>
          <p style="margin:0 0 8px;font-size:13px;line-height:1.6;color:#69758a;">If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="margin:0;word-break:break-all;font-size:13px;line-height:1.6;"><a href="${safeUrl}" style="color:#2459a6;">${safeUrl}</a></p>
        </td>
      </tr>
      <tr>
        <td style="padding:18px 32px;border-top:1px solid #e8edf4;font-size:12px;line-height:1.6;color:#69758a;">
          If you didn't create a Z Namibia account, you can safely ignore this email.
        </td>
      </tr>
    </table>
  </body>
</html>`
  };
}

module.exports = { createVerificationEmail };
