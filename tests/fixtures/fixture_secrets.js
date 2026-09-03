/**
 * tests/fixtures/fixture_secrets.js
 * Fixture: JS file with secret patterns for SECRET_PARAM_PATTERN and HIGH_ENTROPY_PATTERN.
 * Includes the validated Google Maps API key case from PRD 8d/8g.
 *
 * Used by: tests/test_extraction.py
 */

// Case 1: Google Maps key in URL — should be whitelisted to Info (PRD 8g empirical case)
const mapScript = 'https://maps.googleapis.com/maps/api/js?key=AIzaSyBNshGFexamplekey12345678901234';

// Case 2: Generic API key in URL param — should flag HIGH
const weatherUrl = 'https://api.weather.com/v1/data?token=secrettoken123456789012345678';

// Case 3: Secret in query param — should flag
function buildUrl(apiKey) {
    return 'https://api.example.com/data?apikey=' + apiKey + '&format=json';
}

// Case 4: Hardcoded token — HIGH_ENTROPY_PATTERN (Info severity)
const AUTH_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

// Case 5: reCAPTCHA key — should be whitelisted (public by design)
const recaptchaKey = 'https://www.google.com/recaptcha/api.js?key=6LexampleRecaptchaKey1234567890';

// Case 6: Stripe publishable key — acceptable in frontend (but flag for review)
const stripeKey = 'pk_live_51AbcDefGhiJklMnoPqRstUvwXyZ123456789012345678901234567890';

// Case 7: Generic secret keyword (NOT in URL) — should NOT match SECRET_PARAM_PATTERN (correct)
const config = {
    debug: false,
    apiVersion: '2.0'
};

// Case 8: Auth-related function (should match AUTH_FUNCTION_PATTERN)
function validateToken(token) {
    return fetch('/api/auth/verify', { headers: { Authorization: 'Bearer ' + token } });
}

function checkAuth(user) {
    return user && user.role && user.role !== 'guest';
}

function isAdmin(user) {
    return user.role === 'admin';
}
