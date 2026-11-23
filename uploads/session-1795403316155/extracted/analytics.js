// Third-party tracker without consent
fbq('init', '1234567890');
fbq('track', 'Purchase', { email: 'customer@gmail.com', value: 999 });

// Malfunction: empty catch
try {
  doRiskyOperation();
} catch (e) {}

// Plaintext password & HTTP transit
axios.post('http://api.partner.com/sync', {
  user: 'admin',
  password: 'plaintext_password_123',
  aadhaar: '234567890124'
});
