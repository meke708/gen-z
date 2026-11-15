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
  <body style="margin:0;padding:24px;background:#f2f5ef;font-family:Arial,Helvetica,sans-serif;color:#24352c;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;margin:0 auto;background:#ffffff;border:1px solid #dfe8df;border-radius:12px;">
      <tr>
        <td style="padding:24px 30px;background:#18382e;border-radius:12px 12px 0 0;color:#ffffff;">
          <table role="presentation" cellspacing="0" cellpadding="0">
            <tr>
              <td width="48" height="48" align="center" valign="middle" style="width:48px;height:48px;border-radius:50%;background:#18382e;border:2px solid #d8f36a;color:#d8f36a;font-family:Georgia,'Times New Roman',serif;font-size:38px;font-style:italic;font-weight:bold;line-height:44px;">Z</td>
              <td style="padding-left:12px;">
                <div style="font-size:18px;font-weight:bold;letter-spacing:1px;">NAMIBIA</div>
              </td>
            </tr>
          </table>
        </td>
      </tr>
      <tr>
        <td style="padding:30px;">
          <h1 style="margin:0 0 14px;font-size:25px;line-height:1.3;color:#18382e;">Thanks for registering, ${safeName}!</h1>
          <p style="margin:0 0 22px;font-size:16px;line-height:1.6;color:#526257;">Please verify your email address to activate your account.</p>
          <p style="margin:0 0 24px;">
            <a href="${safeUrl}" style="display:inline-block;padding:13px 22px;border-radius:6px;background:#d8f36a;color:#18382e;font-size:15px;font-weight:bold;text-decoration:none;">Verify email address</a>
          </p>
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
