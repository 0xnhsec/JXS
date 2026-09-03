/**
 * tests/fixtures/fixture_endpoints.js
 * Fixture: JS file with various API endpoint patterns for ENDPOINT_PATTERN validation.
 * Expected findings: /api/*, /v1/*, /graphql endpoints
 *
 * Used by: tests/test_extraction.py
 */

// Case 1: REST API path (should match)
const API_BASE = '/api/v1/users';

// Case 2: fetch call with API path (should match)
async function getProfile(userId) {
    const res = await fetch('/api/user/profile/' + userId);
    return res.json();
}

// Case 3: axios call (should match)
async function updateSettings(data) {
    return axios.post('/api/settings/update', data);
}

// Case 4: GraphQL endpoint (should match)
const GRAPHQL_URL = '/graphql';
function fetchQuery(query) {
    return fetch('/graphql', {
        method: 'POST',
        body: JSON.stringify({ query })
    });
}

// Case 5: admin endpoint (should match)
function deleteUser(id) {
    return fetch('/admin/users/' + id, { method: 'DELETE' });
}

// Case 6: auth endpoint (should match)
function login(creds) {
    return axios.post('/auth/login', creds);
}

// Case 7: OAuth callback (should match)
const OAUTH_CALLBACK = '/oauth/callback';

// Case 8: v2 API (should match)
const SEARCH_URL = '/v2/search?q=';

// Case 9: static asset path — NOT an API endpoint (should NOT match as API)
const LOGO = '/static/images/logo.png';

// Case 10: webpack chunk — NOT an endpoint (should NOT match)
const CHUNK = '/dist/chunk-abc123.js';

// Case 11: sourcemap (should match separately by SOURCEMAP_PATTERN)
//# sourceMappingURL=https://example.com/static/js/main.chunk.js.map
