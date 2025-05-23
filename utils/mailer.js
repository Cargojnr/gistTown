// utils/mailer.js
import { Resend } from 'resend';

const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendLoginCodeToUser(user, code, ip, location) {
  const email = user.email;
  const locationInfo = location?.city
    ? `${location.city}, ${location.country}`
    : 'an unknown location';

  const html = `
    <div style="font-family: sans-serif; color: #333;">
      <h2>🔐 Login Verification Code</h2>
      <p>Hi ${user.username || 'there'},</p>
      <p>Your login verification code is:</p>
      <h1>${code}</h1>
      <p>This code will expire in 10 minutes.</p>
      <hr />
      <p><strong>Login Attempt Details:</strong></p>
      <ul>
        <li><strong>IP:</strong> ${ip}</li>
        <li><strong>Location:</strong> ${locationInfo}</li>
        <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
      </ul>
      <p>If this wasn't you, we recommend resetting your password immediately.</p>
    </div>
  `;

  try {
    await resend.emails.send({
      from: 'security@gossipa.com',
      to: email,
      subject: 'Your Gossipa Login Code',
      html,
    });
  } catch (err) {
    console.error('Error sending Resend email:', err);
    throw new Error('Failed to send verification email.');
  }
}
