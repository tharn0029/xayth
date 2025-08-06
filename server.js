// server.js - Real backend for CPI authentication testing
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Test credentials
const VALID_CREDENTIALS = {
    username: 'cpi_user',
    password: 'Test123!',
    clientId: 'cpi_client_123',
    clientSecret: 'secret456'
};

// Simple JWT verification (for demo purposes)
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'your-secret-key';

// Helper function to generate response
function generateResponse(authType, success = true, additionalData = {}) {
    const timestamp = new Date().toISOString();
    return {
        authType,
        success,
        timestamp,
        server: 'CPI-Auth-Practice-Server',
        endpoint: `${authType.toLowerCase().replace(/\s+/g, '-')}-endpoint`,
        ...additionalData
    };
}

// Root endpoint - serve a simple status page
app.get('/', (req, res) => {
    res.json({
        message: 'SAP CPI Authentication Practice Server',
        status: 'running',
        availableEndpoints: {
            'GET /api/no-auth': 'No Authentication Required',
            'GET /api/basic-auth': 'Basic Authentication',
            'POST /api/oauth-token': 'OAuth 2.0 Token Endpoint', 
            'GET /api/oauth-protected': 'OAuth 2.0 Protected Resource',
            'GET /api/client-cert': 'Client Certificate (simulated)',
            'POST /api/jwt-bearer': 'JWT Bearer Token',
            'POST /api/saml-bearer': 'SAML Bearer Assertion',
            'GET /api/api-key': 'API Key Authentication',
            'POST /api/aws-signature': 'AWS Signature V4',
            'GET /api/digest-auth': 'Digest Authentication',
            'GET /api/ntlm-auth': 'NTLM Authentication',
            'POST /api/kerberos-auth': 'Kerberos Authentication'
        },
        testCredentials: {
            basic: 'cpi_user:Test123!',
            oauth: 'cpi_client_123:secret456',
            apiKey: 'CPI-API-KEY-12345',
            samlAssertion: 'valid-saml-assertion'
        },
        timestamp: new Date().toISOString()
    });
});

// 1️⃣ BASIC AUTHENTICATION
app.get('/api/basic-auth', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return res.status(401).json(generateResponse('Basic Auth', false, {
            error: 'Missing or invalid Authorization header',
            expected: 'Authorization: Basic base64(username:password)'
        }));
    }

    try {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        const [username, password] = credentials.split(':');

        if (username === VALID_CREDENTIALS.username && password === VALID_CREDENTIALS.password) {
            res.json(generateResponse('Basic Auth', true, {
                authenticatedUser: username,
                message: 'Successfully authenticated with Basic Auth',
                data: {
                    customerCount: 150,
                    lastSync: new Date().toISOString(),
                    permissions: ['read', 'write']
                }
            }));
        } else {
            res.status(401).json(generateResponse('Basic Auth', false, {
                error: 'Invalid credentials',
                providedUsername: username
            }));
        }
    } catch (error) {
        res.status(400).json(generateResponse('Basic Auth', false, {
            error: 'Invalid base64 encoding in Authorization header'
        }));
    }
});

// 2️⃣ OAUTH 2.0 TOKEN ENDPOINT
app.post('/api/oauth-token', (req, res) => {
    const { grant_type, client_id, client_secret } = req.body;

    if (grant_type !== 'client_credentials') {
        return res.status(400).json({
            error: 'unsupported_grant_type',
            error_description: 'Only client_credentials grant type is supported'
        });
    }

    if (client_id === VALID_CREDENTIALS.clientId && client_secret === VALID_CREDENTIALS.clientSecret) {
        const token = jwt.sign(
            { 
                client_id,
                scope: 'api.read api.write',
                iss: 'cpi-auth-server'
            },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            access_token: token,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'api.read api.write'
        });
    } else {
        res.status(401).json({
            error: 'invalid_client',
            error_description: 'Invalid client credentials'
        });
    }
});

// 3️⃣ OAUTH 2.0 PROTECTED RESOURCE
app.get('/api/oauth-protected', (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json(generateResponse('OAuth 2.0', false, {
            error: 'Missing or invalid Authorization header',
            expected: 'Authorization: Bearer <access_token>'
        }));
    }

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        res.json(generateResponse('OAuth 2.0', true, {
            tokenInfo: {
                client_id: decoded.client_id,
                scope: decoded.scope,
                issuer: decoded.iss,
                expiresAt: new Date(decoded.exp * 1000).toISOString()
            },
            message: 'Successfully authenticated with OAuth 2.0',
            data: {
                resources: ['customers', 'orders', 'products'],
                allowedOperations: decoded.scope.split(' ')
            }
        }));
    } catch (error) {
        res.status(401).json(generateResponse('OAuth 2.0', false, {
            error: 'Invalid or expired token',
            details: error.message
        }));
    }
});

// 4️⃣ NO AUTHENTICATION
app.get('/api/no-auth', (req, res) => {
    res.json(generateResponse('No Auth', true, {
        message: 'This endpoint requires no authentication',
        publicData: {
            serverTime: new Date().toISOString(),
            version: '1.0.0',
            status: 'healthy'
        },
        note: 'Perfect for testing basic connectivity from CPI'
    }));
});

// 5️⃣ CLIENT CERTIFICATE (Simulated)
app.get('/api/client-cert', (req, res) => {
    // In real scenario, you'd check req.connection.getPeerCertificate()
    // For demo, we'll check for a custom header
    const clientCert = req.headers['x-client-cert-cn'];
    
    if (!clientCert) {
        return res.status(401).json(generateResponse('Client Certificate', false, {
            error: 'No client certificate provided',
            note: 'For testing, send X-Client-Cert-CN header with certificate Common Name'
        }));
    }

    res.json(generateResponse('Client Certificate', true, {
        certificateInfo: {
            commonName: clientCert,
            validatedAt: new Date().toISOString(),
            trustLevel: 'high'
        },
        message: 'Successfully authenticated with client certificate',
        data: {
            secureOperations: ['financial-data', 'customer-pii'],
            encryptionLevel: 'AES-256'
        }
    }));
});

// 6️⃣ JWT BEARER TOKEN
app.post('/api/jwt-bearer', (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json(generateResponse('JWT Bearer', false, {
            error: 'Missing or invalid Authorization header',
            expected: 'Authorization: Bearer <jwt_token>'
        }));
    }

    try {
        const token = authHeader.split(' ')[1];
        // For demo, we'll decode without verification (in production, always verify!)
        const decoded = jwt.decode(token, { complete: true });
        
        if (!decoded) {
            throw new Error('Invalid JWT format');
        }

        res.json(generateResponse('JWT Bearer', true, {
            jwtInfo: {
                header: decoded.header,
                payload: decoded.payload,
                validatedAt: new Date().toISOString()
            },
            message: 'Successfully processed JWT Bearer token',
            data: {
                subject: decoded.payload.sub,
                issuer: decoded.payload.iss,
                audience: decoded.payload.aud
            }
        }));
    } catch (error) {
        res.status(401).json(generateResponse('JWT Bearer', false, {
            error: 'Invalid JWT token',
            details: error.message
        }));
    }
});

// 7️⃣ SAML BEARER ASSERTION (Simulated)
app.post('/api/saml-bearer', (req, res) => {
    const samlAssertion = req.headers['x-saml-assertion'] || req.body.saml_assertion;
    
    if (!samlAssertion) {
        return res.status(401).json(generateResponse('SAML Bearer', false, {
            error: 'Missing SAML assertion',
            note: 'For testing, send X-SAML-Assertion header or saml_assertion in body'
        }));
    }

    // Simulate SAML validation (in real world, you'd validate signature, expiry, etc.)
    if (samlAssertion.includes('cpi.company.com') || samlAssertion === 'valid-saml-assertion') {
        res.json(generateResponse('SAML Bearer', true, {
            samlInfo: {
                entityId: 'cpi.company.com',
                assertionId: 'saml-' + Date.now(),
                nameId: 'integration.user@company.com',
                issuer: 'https://adfs.company.com',
                validatedAt: new Date().toISOString()
            },
            message: 'Successfully validated SAML bearer assertion',
            data: {
                userAttributes: {
                    department: 'IT',
                    role: 'Integration Specialist',
                    permissions: ['read', 'write', 'admin']
                }
            }
        }));
    } else {
        res.status(401).json(generateResponse('SAML Bearer', false, {
            error: 'Invalid SAML assertion',
            details: 'Assertion validation failed'
        }));
    }
});

// 8️⃣ API KEY AUTHENTICATION
app.get('/api/api-key', (req, res) => {
    const apiKey = req.headers['x-api-key'] || req.query.api_key;
    const validApiKey = 'CPI-API-KEY-12345';

    if (!apiKey) {
        return res.status(401).json(generateResponse('API Key', false, {
            error: 'Missing API key',
            expected: 'Send X-API-Key header or api_key query parameter'
        }));
    }

    if (apiKey === validApiKey) {
        res.json(generateResponse('API Key', true, {
            apiKeyInfo: {
                keyId: 'cpi-key-001',
                permissions: ['read', 'write'],
                rateLimit: '1000/hour',
                validUntil: '2025-12-31'
            },
            message: 'Successfully authenticated with API key',
            data: {
                allowedEndpoints: ['/customers', '/orders', '/products'],
                quotaRemaining: 995
            }
        }));
    } else {
        res.status(401).json(generateResponse('API Key', false, {
            error: 'Invalid API key',
            providedKey: apiKey.substring(0, 8) + '...'
        }));
    }
});

// 9️⃣ AWS SIGNATURE V4 (Simulated)
app.post('/api/aws-signature', (req, res) => {
    const authHeader = req.headers.authorization;
    const dateHeader = req.headers['x-amz-date'];
    const contentHash = req.headers['x-amz-content-sha256'];

    if (!authHeader || !authHeader.includes('AWS4-HMAC-SHA256')) {
        return res.status(401).json(generateResponse('AWS Signature', false, {
            error: 'Missing or invalid AWS Authorization header',
            expected: 'Authorization: AWS4-HMAC-SHA256 Credential=...'
        }));
    }

    // Simulate AWS signature validation
    if (authHeader.includes('AKIAIOSFODNN7EXAMPLE') && dateHeader && contentHash) {
        res.json(generateResponse('AWS Signature', true, {
            awsInfo: {
                accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
                region: 'us-east-1',
                service: 's3',
                signatureVersion: 'v4',
                validatedAt: new Date().toISOString()
            },
            message: 'Successfully validated AWS Signature V4',
            data: {
                bucketAccess: ['cpi-integration-bucket'],
                allowedOperations: ['GetObject', 'PutObject']
            }
        }));
    } else {
        res.status(403).json(generateResponse('AWS Signature', false, {
            error: 'AWS signature validation failed',
            details: 'Invalid signature or missing required headers'
        }));
    }
});

// 🔟 DIGEST AUTHENTICATION (Simulated)
app.get('/api/digest-auth', (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        // Send WWW-Authenticate challenge
        res.set('WWW-Authenticate', 'Digest realm="CPI Auth Server", nonce="1234567890", algorithm=MD5');
        return res.status(401).json(generateResponse('Digest Auth', false, {
            error: 'Digest authentication required',
            challenge: 'Check WWW-Authenticate header for challenge details'
        }));
    }

    if (authHeader.includes('Digest') && authHeader.includes('username="cpi_user"')) {
        res.json(generateResponse('Digest Auth', true, {
            digestInfo: {
                username: 'cpi_user',
                realm: 'CPI Auth Server',
                algorithm: 'MD5',
                validatedAt: new Date().toISOString()
            },
            message: 'Successfully authenticated with Digest authentication',
            data: {
                sessionTimeout: 3600,
                allowedMethods: ['GET', 'POST', 'PUT']
            }
        }));
    } else {
        res.status(401).json(generateResponse('Digest Auth', false, {
            error: 'Invalid digest authentication',
            details: 'Username or digest validation failed'
        }));
    }
});

// 1️⃣1️⃣ NTLM AUTHENTICATION (Simulated)
app.get('/api/ntlm-auth', (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        res.set('WWW-Authenticate', 'NTLM');
        return res.status(401).json(generateResponse('NTLM Auth', false, {
            error: 'NTLM authentication required',
            note: 'This is a simulation - real NTLM requires multiple round trips'
        }));
    }

    if (authHeader.includes('NTLM') && authHeader.includes('TlRMTVNTUA')) {
        res.json(generateResponse('NTLM Auth', true, {
            ntlmInfo: {
                domain: 'COMPANY',
                username: 'cpi_service',
                workstation: 'CPI-SERVER',
                authenticationType: 'NTLM v2',
                validatedAt: new Date().toISOString()
            },
            message: 'Successfully authenticated with NTLM',
            data: {
                windowsAuth: true,
                domainController: 'dc.company.com'
            }
        }));
    } else {
        res.status(401).json(generateResponse('NTLM Auth', false, {
            error: 'Invalid NTLM authentication',
            details: 'NTLM token validation failed'
        }));
    }
});

// 1️⃣2️⃣ KERBEROS AUTHENTICATION (Simulated)
app.post('/api/kerberos-auth', (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Negotiate ')) {
        res.set('WWW-Authenticate', 'Negotiate');
        return res.status(401).json(generateResponse('Kerberos Auth', false, {
            error: 'Kerberos authentication required',
            expected: 'Authorization: Negotiate <gss-api-token>'
        }));
    }

    // Simulate Kerberos ticket validation
    if (authHeader.includes('YIIEXgYGKwY')) { // Mock Kerberos token
        res.json(generateResponse('Kerberos Auth', true, {
            kerberosInfo: {
                principal: 'cpi-service@COMPANY.COM',
                realm: 'COMPANY.COM',
                ticketType: 'Service Ticket',
                kdc: 'kdc.company.com',
                validatedAt: new Date().toISOString()
            },
            message: 'Successfully authenticated with Kerberos',
            data: {
                ssoEnabled: true,
                ticketLifetime: 28800
            }
        }));
    } else {
        res.status(401).json(generateResponse('Kerberos Auth', false, {
            error: 'Invalid Kerberos ticket',
            details: 'Ticket validation failed'
        }));
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Server error:', error);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        timestamp: new Date().toISOString()
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 SAP CPI Authentication Practice Server running on port ${PORT}`);
    console.log(`📋 Available endpoints:`);
    console.log(`   GET  /                     - Server status`);
    console.log(`   GET  /api/basic-auth       - Basic Authentication`);
    console.log(`   POST /api/oauth-token      - OAuth 2.0 Token`);
    console.log(`   GET  /api/oauth-protected  - OAuth 2.0 Protected`);
    console.log(`   GET  /api/no-auth          - No Authentication`);
    console.log(`   GET  /api/client-cert      - Client Certificate`);
    console.log(`   POST /api/jwt-bearer       - JWT Bearer`);
    console.log(`\n🔐 Test Credentials:`);
    console.log(`   Basic Auth: ${VALID_CREDENTIALS.username}:${VALID_CREDENTIALS.password}`);
    console.log(`   OAuth: ${VALID_CREDENTIALS.clientId}:${VALID_CREDENTIALS.clientSecret}`);
});

module.exports = app;