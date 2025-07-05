# 📚 Vulnerable Bookstore API

> ⚠️ **WARNING: This API is DELIBERATELY INSECURE. DO NOT deploy in production.**

This Express.js API contains intentional vulnerabilities designed for educational purposes and as a demo target for the SecuriScan security analyzer.

## Vulnerabilities

| # | Vulnerability | Endpoint | OWASP Mapping |
|---|--------------|----------|---------------|
| 1 | No Authentication | All endpoints | API2:2023 |
| 2 | IDOR | `GET /api/users/:id` | API1:2023 |
| 3 | Excessive Data Exposure | `GET /api/users/:id` | API3:2023 |
| 4 | No Rate Limiting | All endpoints | API4:2023 |
| 5 | CORS Misconfiguration | All endpoints | API8:2023 |
| 6 | Verbose Error Messages | `GET /api/books/:id` (invalid) | API8:2023 |
| 7 | Unsafe DELETE | `DELETE /api/books/:id` | API5:2023 |
| 8 | Mass Assignment | `PUT /api/users/:id` | API3:2023 |
| 9 | Debug Endpoint | `GET /api/debug` | API8:2023 |

## Setup

```bash
cd vulnerable-api
npm install
npm start
```

The API will start on `http://localhost:4000`.

## Endpoints

- `GET /api/health` — Health check
- `GET /api/books` — List all books
- `GET /api/books/:id` — Get book by ID
- `POST /api/books` — Create a book
- `DELETE /api/books/:id` — Delete a book
- `GET /api/users` — List all users
- `GET /api/users/:id` — Get user by ID
- `PUT /api/users/:id` — Update user
- `GET /api/orders` — List all orders
- `GET /api/orders/:id` — Get order by ID
- `GET /api/debug` — Debug info (intentionally insecure)
