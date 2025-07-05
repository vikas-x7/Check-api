/**
 * ⚠️  DELIBERATELY VULNERABLE API — FOR EDUCATIONAL PURPOSES ONLY
 * 
 * This Bookstore API contains intentional security vulnerabilities
 * designed to be detected by the SecuriScan security analyzer.
 * 
 * DO NOT deploy this in production. This is a demo target only.
 * 
 * Vulnerabilities included:
 * 1. No authentication on any endpoint
 * 2. IDOR — access any user's data by changing ID
 * 3. Excessive data exposure — returns passwords, internal IDs
 * 4. No rate limiting
 * 5. CORS misconfiguration — wildcard origin with credentials
 * 6. Verbose error messages — stack traces, file paths
 * 7. HTTP method issues — DELETE allowed without auth
 * 8. Mass assignment — can set admin=true
 * 9. Debug endpoint — exposes environment variables
 */

/* eslint-disable @typescript-eslint/no-require-imports */

const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 4000;

// ❌ VULNERABILITY: CORS wildcard with credentials
app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
}));

app.use(express.json());

// --- In-memory data store ---
const users = [
    {
        id: 1,
        name: "Alice Johnson",
        email: "alice@bookstore.com",
        password: "$2b$12$LJ3m4ys3LO.hfYLBqIf8OuZ0v5R9GZQ8nFVJ2k3JXbPfSGzR4K6Wm",
        role: "admin",
        ssn: "123-45-6789",
        creditCard: "4111-1111-1111-1111",
        internalId: "USR-001-INTERNAL",
        apiKey: "sk_live_abc123def456ghi789",
        createdAt: "2024-01-15T10:00:00Z"
    },
    {
        id: 2,
        name: "Bob Smith",
        email: "bob@bookstore.com",
        password: "$2b$12$xyz789abc123def456ghijklmnop",
        role: "user",
        ssn: "987-65-4321",
        creditCard: "5500-0000-0000-0004",
        internalId: "USR-002-INTERNAL",
        apiKey: "sk_live_xyz789abc123",
        createdAt: "2024-02-20T14:30:00Z"
    },
    {
        id: 3,
        name: "Charlie Brown",
        email: "charlie@bookstore.com",
        password: "$2b$12$mnopqrstuvwxyz123456789",
        role: "user",
        ssn: "456-78-9012",
        creditCard: "3400-0000-0000-009",
        internalId: "USR-003-INTERNAL",
        apiKey: "sk_live_mnop456qrs789",
        createdAt: "2024-03-10T09:15:00Z"
    }
];

const books = [
    { id: 1, title: "The Art of War", author: "Sun Tzu", price: 12.99, isbn: "978-0140449181", stock: 42 },
    { id: 2, title: "Clean Code", author: "Robert C. Martin", price: 34.99, isbn: "978-0132350884", stock: 15 },
    { id: 3, title: "The Pragmatic Programmer", author: "David Thomas", price: 44.99, isbn: "978-0135957059", stock: 23 },
    { id: 4, title: "Hacking: The Art of Exploitation", author: "Jon Erickson", price: 39.99, isbn: "978-1593271442", stock: 8 },
    { id: 5, title: "Design Patterns", author: "Gang of Four", price: 49.99, isbn: "978-0201633610", stock: 31 },
];

const orders = [
    { id: 1, userId: 1, bookId: 1, quantity: 2, total: 25.98, status: "delivered", secretNote: "VIP customer — free shipping" },
    { id: 2, userId: 2, bookId: 3, quantity: 1, total: 44.99, status: "processing", secretNote: "Use warehouse B" },
    { id: 3, userId: 1, bookId: 2, quantity: 1, total: 34.99, status: "shipped", secretNote: "Priority handling" },
];

// --- Health Check ---
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', version: '1.0.0', uptime: process.uptime() });
});

// --- ❌ VULNERABILITY: No authentication on any endpoint ---

// Books endpoints
app.get('/api/books', (req, res) => {
    res.json(books);
});

app.get('/api/books/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const book = books.find(b => b.id === id);

    if (!book) {
        // ❌ VULNERABILITY: Verbose error with internal details
        const err = new Error(`Book with ID ${id} not found in database`);
        res.status(404).json({
            error: err.message,
            stack: err.stack,
            path: __filename,
            database: "postgresql://admin:secret@db.internal:5432/bookstore",
            debug: { searchedId: id, totalBooks: books.length, nodeEnv: process.env.NODE_ENV }
        });
        return;
    }

    res.json(book);
});

app.post('/api/books', (req, res) => {
    const newBook = { id: books.length + 1, ...req.body };
    books.push(newBook);
    res.status(201).json(newBook);
});

// ❌ VULNERABILITY: DELETE without authentication
app.delete('/api/books/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const index = books.findIndex(b => b.id === id);
    if (index > -1) {
        books.splice(index, 1);
        res.json({ message: "Book deleted", deletedId: id });
    } else {
        res.status(404).json({ error: "Book not found" });
    }
});

// ❌ VULNERABILITY: IDOR — access any user's data
// ❌ VULNERABILITY: Excessive data exposure — returns password, ssn, credit card, api key
app.get('/api/users', (req, res) => {
    res.json(users); // Returns ALL user data including sensitive fields
});

app.get('/api/users/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const user = users.find(u => u.id === id);

    if (!user) {
        res.status(404).json({
            error: "User not found",
            stack: new Error("UserNotFoundError").stack,
            internalPath: "/app/src/controllers/users.js:42"
        });
        return;
    }

    // ❌ Returns ALL fields including password hash, SSN, credit card
    res.json(user);
});

// ❌ VULNERABILITY: Mass assignment — can set role to admin
app.put('/api/users/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const userIndex = users.findIndex(u => u.id === id);

    if (userIndex === -1) {
        res.status(404).json({ error: "User not found" });
        return;
    }

    // Directly merges all request body fields — allows setting role=admin
    users[userIndex] = { ...users[userIndex], ...req.body };
    res.json(users[userIndex]);
});

// Orders endpoints  
app.get('/api/orders', (req, res) => {
    // ❌ Returns ALL orders for ALL users with secret notes
    res.json(orders);
});

app.get('/api/orders/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const order = orders.find(o => o.id === id);

    if (!order) {
        res.status(404).json({ error: "Order not found" });
        return;
    }

    res.json(order);
});

// ❌ VULNERABILITY: Debug endpoint exposing environment
app.get('/api/debug', (req, res) => {
    res.json({
        environment: process.env,
        processInfo: {
            pid: process.pid,
            cwd: process.cwd(),
            memoryUsage: process.memoryUsage(),
            uptime: process.uptime(),
        },
        serverConfig: {
            database: "postgresql://admin:secret@db.internal:5432/bookstore",
            secretKey: "super-secret-jwt-key-do-not-share",
            apiKeys: ["sk_live_abc123", "sk_test_xyz789"],
        }
    });
});

// Error handling
app.use((err, req, res, _next) => { // eslint-disable-line @typescript-eslint/no-unused-vars
    // ❌ VULNERABILITY: Verbose error responses in all environments
    res.status(500).json({
        error: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
    });
});

app.listen(PORT, () => {
    console.log(`
  ⚠️  VULNERABLE BOOKSTORE API — FOR TESTING ONLY
  📚 Running on http://localhost:${PORT}
  
  Endpoints:
    GET    /api/health
    GET    /api/books
    GET    /api/books/:id
    POST   /api/books
    DELETE /api/books/:id
    GET    /api/users
    GET    /api/users/:id
    PUT    /api/users/:id
    GET    /api/orders
    GET    /api/orders/:id
    GET    /api/debug
  `);
});
