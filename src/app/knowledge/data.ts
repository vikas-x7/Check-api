export type KnowledgeItem = {
    id: string;
    title: string;
    category: string;
    shortDescription: string;
    longDescription: string;
    severity?: "Critical" | "High" | "Medium" | "Low" | "Info";
    color: string;
    vulnerableCode?: string;
    secureCode?: string;
    explanation: string;
    attackScenario?: string;
    howToPrevent?: string[];
    bestPractices?: string[];
    implementationGuide?: string;
};

export const knowledgeItems: KnowledgeItem[] = [
    // OWASP API Security Top 10 (2023)
    {
        id: "api1-bola",
        title: "Broken Object Level Authorization",
        category: "owasp",
        shortDescription: "Attackers manipulate object IDs to access unauthorized data.",
        longDescription: "APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface Level Access Control issue. Object level authorization checks should be considered in every function that accesses a data source using an input from the user. BOLA occurs when an application does not properly validate if the currently authenticated user has the necessary permissions to access, modify, or delete a specific object.",
        severity: "Critical",
        color: "from-red-500 to-rose-600",
        vulnerableCode: `// Route: GET /api/users/:userId/financial-data
app.get("/api/users/:userId/financial-data", async (req, res) => {
    //  VULNERABLE: Uses requested userId from URL without verifying if 
    // the logged-in user actually owns this userId.
    const requestedUserId = req.params.userId;
    const data = await Database.getFinancialData(requestedUserId);
    res.json(data);
});`,
        secureCode: `// Route: GET /api/users/:userId/financial-data
app.get("/api/users/:userId/financial-data", async (req, res) => {
    const requestedUserId = req.params.userId;
    const loggedInUser = req.user; // From Auth Middleware
    
    //  SECURE: Verify ownership or admin rights before retrieving data
    if (requestedUserId !== loggedInUser.id && loggedInUser.role !== "ADMIN") {
        return res.status(403).json({ error: "Access denied" });
    }
    
    const data = await Database.getFinancialData(requestedUserId);
    res.json(data);
});`,
        explanation: "By relying purely on the Object ID passed in the request, the application mistakenly trusts the client. Attackers can simply write a script to iterate over Object IDs (e.g. user=1, user=2, user=3) and steal the entirety of the database.",
        attackScenario: "An attacker intercepts an API call `GET /api/receipts/19452`. They change the ID to `19453` and unexpectedly receive another user's shopping receipt, containing their home address and last four digits of their credit card.",
        howToPrevent: [
            "Implement a strict authorization mechanism that relies on the user policies and hierarchy.",
            "Use the authorization mechanism to check if the logged-in user has access to perform the requested action on the record.",
            "Prefer the use of random and unpredictable values as GUIDs for records' IDs.",
            "Write tests specifically to evaluate the vulnerability of the authorization mechanism."
        ]
    },
    {
        id: "api2-broken-auth",
        title: "Broken Authentication",
        category: "owasp",
        shortDescription: "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.",
        longDescription: "Authentication endpoints are exposed to anyone by design. Because of this, software engineers need to write highly secure authentication logic to prevent attackers from compromising passwords, keys, or session tokens. If authentication is broken, attackers can temporarily or permanently assume the identities of other users, leading to full system compromise.",
        severity: "Critical",
        color: "from-purple-500 to-fuchsia-600",
        vulnerableCode: `//  VULNERABLE: No rate limiting on login endpoint
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await Database.findUser(username);
    
    // Attacker can bruteforce passwords millions of times
    if (user && await bcrypt.compare(password, user.password)) {
        res.json({ token: generateToken(user) });
    } else {
        res.status(401).send("Invalid credentials");
    }
});`,
        secureCode: `import rateLimit from "express-rate-limit";

//  SECURE: Apply strict rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per window
    message: "Too many login attempts, please try again later"
});

app.post("/api/login", loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const user = await Database.findUser(username);
    
    if (user && await bcrypt.compare(password, user.password)) {
        res.json({ token: generateToken(user) });
    } else {
        res.status(401).send("Invalid credentials");
    }
});`,
        explanation: "Attackers frequently use automated brute-force attacks and credential stuffing using leaked passwords. Without rate limiting, account lockout mechanisms, and proper verification, your API will fall to these automated scripts.",
        attackScenario: "An attacker acquires a massive database of breached passwords from a different service. They write a bot that repeatedly hits your `/api/user/login` endpoint using those email/password combinations until it successfully logs into an admin account.",
        howToPrevent: [
            "Ensure you know all the possible flows to authenticate to the API.",
            "Implement multi-factor authentication where possible.",
            "Implement anti-brute force mechanisms to mitigate credential stuffing and dictionary attacks.",
            "Don't put sensitive authentication tokens in the URL."
        ]
    },
    {
        id: "api3-bopla",
        title: "Broken Object Property Level Authorization",
        category: "owasp",
        shortDescription: "APIs expose or allow modification of object properties that should not be accessible.",
        longDescription: "This category combines the previously known Mass Assignment and Excessive Data Exposure vulnerabilities. When designing APIs, developers often expose all object properties by default, blindly trusting the client window to filter out sensitive attributes. Conversely, APIs may accept client updates and blindly merge them into internal records, allowing attackers to overwrite sensitive internal fields like 'isAdmin', 'payment_status', or 'balance'.",
        severity: "High",
        color: "from-pink-500 to-rose-500",
        vulnerableCode: `//  VULNERABLE: Blindly overriding existing database record
app.put("/api/users/:id", async (req, res) => {
    const userId = req.params.id;
    const updateData = req.body; // Client sends { name: "Bob", role: "admin" }
    
    // The database blindly updates all provided fields!
    const updatedUser = await Database.updateUser(userId, updateData);
    
    // Additionally, all fields (including password hashes) might be returned!
    res.json(updatedUser); 
});`,
        secureCode: `//  SECURE: Explicitly picking allowed properties
app.put("/api/users/:id", async (req, res) => {
    const userId = req.params.id;
    
    // Only allow updating specific, non-sensitive fields
    const safeData = {
        name: req.body.name,
        profilePicture: req.body.profilePicture,
        bio: req.body.bio
    };
    
    const updatedUser = await Database.updateUser(userId, safeData);
    
    // Also, explicitly select what to return!
    res.json({
        id: updatedUser.id,
        name: updatedUser.name,
        bio: updatedUser.bio
    });
});`,
        explanation: "If you simply take `req.body` and feed it into an ORM's `update()` function, you are trusting the client not to pass malicious overriding keys. You must strictly sanitize the input payloads.",
        attackScenario: "A ride-sharing application provides the option to change basic profile info. An attacker captures the request and adds `\"wallet_balance\": 99999` to their JSON packet. The backend blindly updates their database balance, getting free rides.",
        howToPrevent: [
            "When exposing an object using an API endpoint, always make sure that the user should have access to the object's properties.",
            "Avoid using functions that automatically bind a client's input into code variables or internal objects.",
            "Only allow updating properties that should be updated.",
            "Implement a schema-based response validation mechanism as an extra layer of security."
        ]
    },
    {
        id: "api4-urc",
        title: "Unrestricted Resource Consumption",
        category: "owasp",
        shortDescription: "Lack of rate limiting and limits on resource usage leads to Denial of Service and high cloud bills.",
        longDescription: "APIs require varying degrees of compute power, storage, and network bandwidth to fulfill client requests. If an API has no limits on how often it can be called, the size of payloads it processes, or the number of database records it fetches per request, malicious or simply buggy clients can consume so many resources that the server crashes, becomes unresponsive to legitimate users, or drives up cloud usage costs.",
        severity: "High",
        color: "from-emerald-500 to-teal-600",
        vulnerableCode: `//  VULNERABLE: No limits on payload or pagination
app.post("/api/reports/generate", async (req, res) => {
    // 1. Accepts ANY file size uploaded by client
    // 2. Client can request 10,000,000 rows at once
    const { limit = 10000000, dataPayload } = req.body; 
    
    // Database crashes trying to load millions of rows into RAM
    const reportData = await Database.getMassiveData(limit);
    
    // Node.js Event Loop gets blocked processing enormous payload
    const pdf = await expensivePDFGenerator(reportData, dataPayload);
    
    res.sendFile(pdf);
});`,
        secureCode: `//  SECURE: Strict payload and pagination restrictions
app.post("/api/reports/generate", 
   bodyParser.json({ limit: '100kb' }), // Restrict payload size
   rateLimiter({ max: 5, windowMs: 60000 }), // Restrict request rate
   async (req, res) => {
    
    // Force pagination maximums
    let limit = parseInt(req.body.limit) || 50;
    if (limit > 100) limit = 100;
    
    const reportData = await Database.getMassiveData(limit);
    
    // Queue expensive operations via background workers instead of blocking
    const jobId = await taskQueue.add("pdf-generation", reportData);
    
    res.status(202).json({ status: "Processing", jobId });
});`,
        explanation: "You must consider memory and CPU consumption for every single API endpoint. Enforce pagination, implement rate-limiting, offload heavy computations to background queues, and limit incoming JSON payload sizes.",
        attackScenario: "A competitor discovers a GraphQL endpoint for an e-commerce site and submits a deeply nested analytical query string that targets thousands of items while requesting full relational nested expansion. The database locks up and the site goes down on Black Friday.",
        howToPrevent: [
            "Use a solution that makes it easy to limit memory, CPU, number of restarts, file descriptors, and processes.",
            "Implement a limit on how often a client can call the API within a defined timeframe.",
            "Limit the maximum size of incoming data.",
            "Enforce strict limits on pagination.",
            "Define maximum constraints for string lengths and array sizes natively."
        ]
    },
    {
        id: "api5-bfla",
        title: "Broken Function Level Authorization",
        category: "owasp",
        shortDescription: "Failing to restrict access to sensitive functional actions like 'deleteUser' or 'exportData'.",
        longDescription: "Complex access control policies with different hierarchies, groups, and roles, and an unclear separation between administrative and regular functions lead to authorization flaws. By exploiting these issues, attackers access other users' resources and/or administrative functions. Unlike BOLA (which targets specific Object ID access), BFLA occurs when the entire function (endpoint itself) is illegally accessible.",
        severity: "High",
        color: "from-blue-500 to-cyan-600",
        vulnerableCode: `//  VULNERABLE: Assuming only the admin web panel calls this API
// The developer hid the button on the frontend, but left the backend open.
app.delete("/api/companies/:id", async (req, res) => {
    // There is no check to see if req.user is an Administrator
    await Database.deleteCompany(req.params.id);
    res.json({ success: true });
});`,
        secureCode: `//  SECURE: Verify the function-level privilege of the user
app.delete("/api/companies/:id", async (req, res) => {
    // Reject access if the user lacks the explicit 'ADMIN' role
    if (!req.user || req.user.role !== "SUPER_ADMIN") {
        return res.status(403).json({ error: "Insufficient privileges" });
    }
    
    await Database.deleteCompany(req.params.id);
    res.json({ success: true });
});`,
        explanation: "Security through obscurity (like hiding a UI button) is completely ineffective against API attacks. Attackers bypass the UI and probe API endpoints directly. You must explicitly evaluate authorization for every single programmatic function executed on the backend.",
        attackScenario: "An attacker intercepts traffic while using a normal user account and notices endpoints like `/api/v1/users/view`. They manually guess the existence of `/api/v1/users/exportAll` based on typical naming conventions and successfully trigger a full database dump because the endpoint had no 'isAdmin' requirement.",
        howToPrevent: [
            "Your application should have a consistent and easy-to-analyze authorization module that is invoked from all your business functions.",
            "By default, deny all access and explicitly grant access for specific roles.",
            "Review your API endpoints against privilege flaws.",
            "Make sure that all administrative controllers inherit from an abstract controller that implements authorization checks."
        ]
    },
    {
        id: "api6-uasbf",
        title: "Unrestricted Access to Sensitive Business Flows",
        category: "owasp",
        shortDescription: "Automated bots abusing legitimate logic flows like ticket purchasing or comment spamming.",
        longDescription: "APIs vulnerable to this risk expose a business flow - such as buying a ticket, posting a comment, creating an account, or reserving a seat - without taking measures to prevent automated abuse. The API functions perfectly according to specification, but the lack of anti-automation defense allows malicious bots to scalp inventory, poison analytics, spam forums, or manipulate economies.",
        severity: "Medium",
        color: "from-indigo-500 to-blue-600",
        vulnerableCode: `//  VULNERABLE: A purchase endpoint that can be scripted instantly
app.post("/api/tickets/purchase", async (req, res) => {
    const { eventId, qty, paymentInfo } = req.body;
    
    // Bots can submit this POST request 1,000 times per second
    const success = await processPayment(paymentInfo, qty);
    if(success) {
        await issueTickets(eventId, qty);
        res.json({ status: "purchased" });
    }
});`,
        secureCode: `//  SECURE: Employ anti-automation and CAPTCHA validation
app.post("/api/tickets/purchase", async (req, res) => {
    const { eventId, qty, paymentInfo, captchaToken } = req.body;
    
    // Require a valid CAPTCHA token generated by human-interaction
    const isHuman = await verifyCaptcha(captchaToken);
    if (!isHuman) return res.status(403).json({ error: "Bot detected" });
    
    // Ensure the current user hasn't bought more than the global limit
    if (await overPurchaseLimit(req.user.id)) {
        return res.status(429).json({ error: "Ticket limit reached" });
    }
    
    const success = await processPayment(paymentInfo, qty);
    if(success) {
        await issueTickets(eventId, qty);
        res.json({ status: "purchased" });
    }
});`,
        explanation: "APIs must differentiate between a human using the official app and a scripted bot abusing the endpoint. Rate limiting by IP is not enough, as bots use vast proxies. You must implement Device Fingerprinting, CAPTCHAs, or anomaly behavior mapping to protect business flows.",
        attackScenario: "A scalping group deploys a script against the `/api/checkout` endpoint for an electronics store. The millisecond a new graphics card goes out of stock, their bot purchases all 5,000 units before legitimate customers' web browsers even render the 'Add To Cart' button.",
        howToPrevent: [
            "Identify what business flows might be harmed by excessive automation.",
            "Consider device fingerprinting to deny traffic from headless browsers or known botnets.",
            "Require human interactions (e.g. CAPTCHA, biometric auth) for highly sensitive transactional actions.",
            "Implement intelligent rate limiting that goes beyond raw IP counting (e.g., analyze the flow sequence)."
        ]
    },
    {
        id: "api7-ssrf",
        title: "Server-Side Request Forgery",
        category: "owasp",
        shortDescription: "Attackers force the server to execute malicious outbound network requests to internal systems.",
        longDescription: "Server-Side Request Forgery (SSRF) flaws occur whenever an API is fetching a remote URI without validating the user-supplied URI. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or network ACL.",
        severity: "High",
        color: "from-sky-500 to-cyan-600",
        vulnerableCode: `//  VULNERABLE: Blindly downloading user-supplied URL
app.post("/api/profile/import-avatar", async (req, res) => {
    const { avatarUrl } = req.body;
    
    // Attacker sends: "http://169.254.169.254/latest/meta-data/"
    // The server fetches its own AWS cloud metadata and returns it!
    const response = await fetch(avatarUrl);
    const data = await response.text();
    
    await Database.saveAvatar(req.user.id, data);
    res.json({ success: true, preview: data });
});`,
        secureCode: `//  SECURE: Validate URL format, scheme, and destination IP
app.post("/api/profile/import-avatar", async (req, res) => {
    const { avatarUrl } = req.body;
    const urlObj = new URL(avatarUrl);
    
    // 1. Force HTTPS and restrict domains
    if (urlObj.protocol !== "https:") return res.status(400).send("HTTPS required");
    
    // 2. Disallow local network ranges and cloud metadata IPs
    const ip = await resolveIp(urlObj.hostname);
    if (isInternalNetwork(ip) || ip === "169.254.169.254") {
        return res.status(403).send("Invalid destination");
    }
    
    const response = await fetch(avatarUrl);
    res.json({ success: true });
});`,
        explanation: "Modern web applications frequently fetch data from external sources (e.g., webhooks, unfurling link previews, importing images). If attackers supply internal IPs (`127.0.0.1`) or Cloud Metadata IPs (`169.254.169.254`), they can extract confidential server configurations, database passwords, and AWS credentials.",
        attackScenario: "A developer builds an endpoint to fetch RSS feeds. An attacker passes `http://localhost:6379/` (Redis server default port) as the URL. The backend server establishes a TCP connection to its own internal unprotected Redis database and returns its internal secret keys back to the attacker as 'RSS content'.",
        howToPrevent: [
            "Isolate the resource fetching mechanism in your network (e.g. routing outbound traffic through a strict proxy).",
            "Disable HTTP redirections.",
            "Use a well-maintained and strict allowlist of schemas and hosts.",
            "Validate client-supplied input data including the DNS resolution of the provided URL to block local IP resolutions."
        ]
    },
    {
        id: "api8-sec-misconfig",
        title: "Security Misconfiguration",
        category: "owasp",
        shortDescription: "Leaving default configurations, using unpatched systems, and lacking secure headers.",
        longDescription: "APIs and the systems supporting them typically contain complex configurations meant to make the servers more customizable. Security misconfiguration occurs when these default configurations fail to properly protect the application—such as failing to enforce HTTPS, allowing dangerous HTTP methods (like PUT or TRACE), keeping default usernames/passwords, or dumping verbose stack traces into production responses.",
        severity: "High",
        color: "from-stone-500 to-neutral-600",
        vulnerableCode: `//  VULNERABLE: Permissive CORS and verbose errors
const app = express();

// Allows ANY domain to send authenticated requests!
app.use(cors({ origin: "*", credentials: true })); 

app.use((err, req, res, next) => {
    // Leaks file paths, database queries, and Node versions
    res.status(500).json({ error: err.message, stack: err.stack });
});`,
        secureCode: `//  SECURE: Restrictive CORS and sanitized error messages
const app = express();

// Explicitly whitelist trusted frontend domains
app.use(cors({ 
    origin: ["https://mycompany.com", "https://app.mycompany.com"],
    credentials: true 
})); 

app.use((err, req, res, next) => {
    // Log the actual error internally to Elastic/Datadog
    logger.error("API Failure", { error: err.message, stack: err.stack });
    
    // Return a generalized error to the end user
    res.status(500).json({ error: "An unexpected error occurred." });
});`,
        explanation: "Security misconfigurations often emerge from 'rapid deployment' mindsets where teams rely on default settings. These defaults are configured for maximum compatibility, not maximum security. You must 'harden' your deployment by disabling all unused features.",
        attackScenario: "A backend error occurs when fetching a user profile due to a typo in the database query. Because error verbosity wasn't turned off in production, the backend returns the full SQL connection string with the raw database password in the HTTP 500 JSON response, which the attacker copies.",
        howToPrevent: [
            "Establish a repeatable, automated hardening process for environments.",
            "Review and update configurations across the entire API stack (API gateways, servers, databases).",
            "Securely segregate tenant data using strict CORS policies.",
            "Remove or disable all unused features and endpoints out of production environments."
        ]
    },
    {
        id: "api9-improper-inventory",
        title: "Improper Inventory Management",
        category: "owasp",
        shortDescription: "Ignoring shadow APIs, abandoning old API versions, and lack of API documentation.",
        longDescription: "APIs tend to expose more endpoints than traditional web apps, making proper and updated documentation highly important. Improper Inventory Management includes running unpatched, deprecated API versions (e.g., `/api/v1/`) alongside new versions, or forgetting about 'shadow APIs' deployed for testing purposes that lack modern authentication logic.",
        severity: "Medium",
        color: "from-amber-500 to-yellow-600",
        vulnerableCode: `//  VULNERABLE: Ghost/deprecated API routing left in the application
app.use("/api/v3/users", authMiddleware, v3UsersRouter);

// The developers implemented modern security in v3, but forgot 
// to delete v1, which STILL connects to the production database!
app.use("/api/v1/users", legacyV1UsersRouter); 

// A developer pushed an undocumented endpoint for testing locally
app.get("/api/test/dump_db", async (req, res) => {
    res.json(await Database.dumpAll());
});`,
        secureCode: `//  SECURE: Strict routing with deprecated API removal
app.use("/api/v3/users", authMiddleware, v3UsersRouter);

// All older/unsupported versions strictly disabled or firmly rate-limited
app.use("/api/v1/*", (req, res) => res.status(410).send("API v1 is deprecated. Upgrade to v3."));
app.use("/api/v2/*", (req, res) => res.status(410).send("API v2 is deprecated. Upgrade to v3.");

// Ensure testing endpoints ONLY exist in non-production environments
if (process.env.NODE_ENV === "development") {
    app.get("/api/test/metrics", testHandler);
}`,
        explanation: "Attackers commonly use automated tools to brute-force directory paths and discover older API versions. If `api.company.com/v3/` is heavily defended by state-of-the-art protections, but `api.company.com/v1/` is still routing to the same database but using legacy, vulnerable logic, the attacker will just exploit V1.",
        attackScenario: "An attacker realizes that `/api/v2/reset_password` requires a complex 2FA token. They maliciously try `/api/v1/reset_password`—an endpoint deprecated two years ago but never deleted from the codebase. The V1 endpoint only requires an email address and successfully resets the password of an administrator without 2FA.",
        howToPrevent: [
            "Inventory all API hosts and document your API architecture using tools like OpenAPI/Swagger.",
            "Implement API gateways to automatically throttle or redirect traffic away from deprecated routes.",
            "Establish strict retirement policies for old APIs.",
            "Use external protection (such as Web Application Firewalls) for all API endpoints uniformly."
        ]
    },
    {
        id: "api10-unsafe-consumption",
        title: "Unsafe Consumption of APIs",
        category: "owasp",
        shortDescription: "APIs blindly trusting data received from other third-party APIs.",
        longDescription: "Developers often trust data received from third-party APIs more than user input, assuming the external provider has already sanitized it. This is a fatal assumption. If the external provider is breached, hijacked, or manipulated, your application will ingest malicious data (like SQL injection strings or Cross-Site Scripting scripts) leading to system compromise.",
        severity: "High",
        color: "from-teal-500 to-emerald-600",
        vulnerableCode: `//  VULNERABLE: Blindly trusting data from a partner API
app.get("/api/integrations/sync", async (req, res) => {
    // Fetching data from an external supplier API
    const response = await fetch("https://external-supplier.com/api/products");
    const externalProducts = await response.json();
    
    // Blindly inserting third-party text directly into an SQL database
    // If the external supplier is breached, they can execute SQL Injection on US!
    for (let product of externalProducts) {
        await BaseDB.execute(
            \`INSERT INTO products (name) VALUES ('\${product.name}')\`
        );
    }
    res.json({ success: true });
});`,
        secureCode: `//  SECURE: Validate and sanitize data from third parties
app.get("/api/integrations/sync", async (req, res) => {
    const response = await fetch("https://external-supplier.com/api/products");
    const externalProducts = await response.json();
    
    // Always use parameterized queries (Prepared Statements)
    // Validate the external data format using a strict schema parser (like Zod)
    const validProducts = productSchema.parse(externalProducts);
    
    for (let product of validProducts) {
        await BaseDB.execute(
            'INSERT INTO products (name) VALUES ($1)', 
            [product.name]
        );
    }
    res.json({ success: true });
});`,
        explanation: "APIs don't operate in a vacuum. Most enterprise APIs reach out to payment processors, external CRMs, and partner APIs. Never trust any input that your application did not generate directly. Treat all external network traffic as adversarial.",
        attackScenario: "Your API automatically pulls weather data from a targeted external API and displays it on thousands of smart IoT devices. Attackers compromise the weather API provider and change the 'City Name' field to a massive malicious firmware exploit string, crashing all your devices instantaneously.",
        howToPrevent: [
            "When evaluating service providers, assess their API security posture.",
            "Ensure all data interactions occurring between your application and an external API happen over a secure communication channel (TLS).",
            "Always validate and properly sanitize data received from external APIs before processing it.",
            "Maintain an explicit allowlist of external locations your API is permitted to talk to."
        ]
    },

    // Common Vulnerability Types
    {
        id: "sqli",
        title: "SQL Injection",
        category: "vulnerabilities",
        shortDescription: "Attackers inject malicious SQL code through user inputs to manipulate database queries.",
        longDescription: "SQL Injection occurs when untrusted data is inserted into an SQL query. Attackers can manipulate the inputs to inject their own SQL commands, potentially bypassing authentication, retrieving, modifying, or deleting database data. This is one of the oldest and most dangerous web application vulnerabilities.",
        severity: "Critical",
        color: "from-red-600 to-orange-600",
        vulnerableCode: `//  VULNERABLE: Direct string concatenation in SQL query
app.get("/api/users", async (req, res) => {
    const username = req.query.username;
    
    // Attacker input: ' OR '1'='1
    const query = \`SELECT * FROM users WHERE username = '\${username}'\`;
    const users = await db.query(query);
    
    res.json(users);
});`,
        secureCode: `//  SECURE: Using parameterized queries (Prepared Statements)
app.get("/api/users", async (req, res) => {
    const username = req.query.username;
    
    // Database driver handles escaping automatically
    const query = 'SELECT * FROM users WHERE username = $1';
    const users = await db.query(query, [username]);
    
    res.json(users);
});

// Also recommended: Use an ORM like Prisma or Sequelize`,
        explanation: "SQL injection exploits the way SQL queries are constructed. When user input is directly concatenated into SQL strings, attackers can escape the intended query structure and inject their own commands. Parameterized queries treat user input as data, not executable code.",
        attackScenario: "A login form accepts username input. An attacker enters `admin'--` which completes the query as `SELECT * FROM users WHERE username = 'admin'--' (commenting out the password check). The attacker gains admin access without knowing the password.",
        howToPrevent: [
            "Always use parameterized queries or prepared statements.",
            "Use an ORM (Object-Relational Mapping) library when possible.",
            "Validate and sanitize all user inputs.",
            "Apply the principle of least privilege for database accounts."
        ]
    },
    {
        id: "nosqli",
        title: "NoSQL Injection",
        category: "vulnerabilities",
        shortDescription: "Injection attacks targeting NoSQL databases like MongoDB through malformed query operators.",
        longDescription: "NoSQL injection occurs when attackers inject malicious code into NoSQL database queries. Unlike SQL injection, these attacks use MongoDB operators like $where, $gt, or $regex to bypass authentication, extract data, or execute arbitrary JavaScript on the database server.",
        severity: "Critical",
        color: "from-red-600 to-pink-600",
        vulnerableCode: `//  VULNERABLE: Passing user input directly to MongoDB query
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    
    // Attacker can send: { "$gt": "" } as username to bypass auth
    const user = await db.collection("users").findOne({
        username: username,
        password: password
    });
    
    if (user) {
        res.json({ token: generateToken(user) });
    }
});`,
        secureCode: `//  SECURE: Validate input types and use strict queries
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    
    // Ensure username and password are strings
    if (typeof username !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "Invalid input types" });
    }
    
    // Use explicit equality operators, not operators from input
    const user = await db.collection("users").findOne({
        username: { $eq: username },
        password: { $eq: password }
    });
    
    if (user) {
        res.json({ token: generateToken(user) });
    }
});`,
        explanation: "NoSQL databases like MongoDB use JSON-like query syntax. When user input is passed directly to database queries without validation, attackers can inject MongoDB operators that alter the query logic. Always validate input types and use explicit value matching.",
        attackScenario: "A login endpoint accepts JSON body. An attacker sends `{\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}`. MongoDB's $gt operator matches anything greater than empty string, so the query matches the first user in the database, granting unauthorized access.",
        howToPrevent: [
            "Validate and sanitize all user inputs before using them in queries.",
            "Use strict type checking on all inputs.",
            "Avoid using $where or $function operators with user input.",
            "Use an ORM/ODM that handles query building safely."
        ]
    },
    {
        id: "jwt-vulns",
        title: "JWT Token Vulnerabilities",
        category: "vulnerabilities",
        shortDescription: "Weak JWT implementation allowing token forgery, algorithm confusion, and secret key exposure.",
        longDescription: "JSON Web Tokens (JWT) are widely used for authentication and authorization. However, improper JWT implementation can lead to severe vulnerabilities including algorithm confusion attacks, weak signing keys, missing expiration checks, and information disclosure through unencrypted tokens.",
        severity: "High",
        color: "from-purple-600 to-indigo-600",
        vulnerableCode: `//  VULNERABLE: No signature verification and weak secret
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await findUser(username, password);
    
    if (user) {
        // Weak secret that attackers can easily guess
        const token = jwt.sign(
            { userId: user.id, role: user.role },
            "secret123",  // Weak secret!
            { expiresIn: "24h" }
        );
        res.json({ token });
    }
});

// Middleware without proper verification
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (token) {
        req.user = jwt.decode(token);  // No verification!
        next();
    }
};`,
        secureCode: `//  SECURE: Proper JWT implementation with strong secrets
import jwt from "jsonwebtoken";

// Use strong, randomly generated secrets stored in environment variables
const JWT_SECRET = process.env.JWT_SECRET; // Should be at least 256 bits
const JWT_ALGORITHM = "HS256";

app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await findUser(username, password);
    
    if (user) {
        const token = jwt.sign(
            { 
                userId: user.id, 
                role: user.role,
                iat: Math.floor(Date.now() / 1000)
            },
            JWT_SECRET,
            { 
                expiresIn: "1h",
                algorithm: JWT_ALGORITHM
            }
        );
        res.json({ token });
    }
});

// Proper verification middleware
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "No token" });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET, {
            algorithms: [JWT_ALGORITHM]
        });
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Invalid token" });
    }
};`,
        explanation: "JWT vulnerabilities arise from improper implementation. Common issues include: using 'none' algorithm, weak secrets, not verifying signatures, storing sensitive data in payload, and not checking expiration. Always verify signatures server-side and use strong, unique secrets.",
        attackScenario: "An attacker obtains a JWT token. They decode the payload, change the role to 'admin', and re-encode with algorithm set to 'none'. Some libraries accept this modified token without signature verification, granting admin privileges.",
        howToPrevent: [
            "Use strong, randomly generated secrets stored in environment variables.",
            "Always verify the signature on the server side.",
            "Explicitly specify and validate the algorithm.",
            "Check token expiration (exp claim).",
            "Don't store sensitive data in JWT payload without encryption."
        ]
    },
    {
        id: "cors-misconfig",
        title: "CORS Misconfiguration",
        category: "vulnerabilities",
        shortDescription: "Improperly configured Cross-Origin Resource Sharing allowing unauthorized cross-site access.",
        longDescription: "CORS (Cross-Origin Resource Sharing) is a mechanism that allows restricted resources on a web page to be requested from another domain. Misconfigured CORS can allow malicious websites to make authenticated requests to your API, leading to data theft and CSRF-like attacks.",
        severity: "Medium",
        color: "from-amber-500 to-yellow-500",
        vulnerableCode: `//  VULNERABLE: Overly permissive CORS policy
const app = express();

// Allows ANY website to make authenticated requests!
app.use(cors({
    origin: "*",  // Accepts any origin!
    credentials: true
}));

app.get("/api/user/profile", authMiddleware, (req, res) => {
    // Any website can fetch this data
    res.json(req.user);
});`,
        secureCode: `//  SECURE: Strict CORS configuration
const app = express();

// Whitelist only trusted domains
const allowedOrigins = [
    "https://yourdomain.com",
    "https://app.yourdomain.com"
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or Postman)
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error("Not allowed by CORS"));
        }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

// Also consider:
app.use(helmet()); // Sets secure headers by default`,
        explanation: "CORS misconfiguration occurs when APIs accept requests from any origin ('*') or improperly validate the Origin header. This allows attackers to create malicious websites that make authenticated requests to your API, bypassing Same-Origin Policy protections.",
        attackScenario: "A user is logged into your banking app. They visit a malicious website that makes a fetch() request to your API's `/api/transfer` endpoint. Because CORS allows any origin, the malicious site can read the response and steal the user's data.",
        howToPrevent: [
            "Whitelist specific trusted origins instead of using '*'.",
            "Validate the Origin header server-side.",
            "Use credentials: true only with whitelisted origins.",
            "Consider using a WAF (Web Application Firewall).",
            "Use security headers like Helmet.js."
        ]
    },
    {
        id: "rate-limiting-issues",
        title: "Rate Limiting Issues",
        category: "vulnerabilities",
        shortDescription: "Missing or improperly configured rate limiting allowing brute force and DoS attacks.",
        longDescription: "Without proper rate limiting, APIs are vulnerable to brute force attacks, credential stuffing, scraping, and Denial of Service attacks. Rate limiting should be applied at multiple levels: IP address, user account, API endpoint, and globally.",
        severity: "Medium",
        color: "from-orange-500 to-red-500",
        vulnerableCode: `//  VULNERABLE: No rate limiting on sensitive endpoints
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    // Attacker can try millions of passwords per second
    const user = await authenticate(username, password);
    
    if (user) {
        res.json({ success: true });
    } else {
        res.status(401).json({ error: "Invalid credentials" });
    }
});

app.get("/api/search", async (req, res) => {
    // Database can be overwhelmed with complex queries
    const results = await searchDatabase(req.query.q);
    res.json(results);
});`,
        secureCode: `//  SECURE: Implement rate limiting on all endpoints
import rateLimit from "express-rate-limit";

// Strict rate limiting for authentication
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Only 5 attempts per window
    message: "Too many login attempts",
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false
});

// Moderate rate limiting for search
const searchLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30,
    message: "Too many search requests"
});

app.post("/api/login", loginLimiter, async (req, res) => {
    // Login logic
});

app.get("/api/search", searchLimiter, async (req, res) => {
    // Search logic
});`,
        explanation: "Rate limiting restricts how many requests a client can make within a time window. Without it, attackers can use automated tools to make thousands of requests per second, enabling brute force attacks, credential stuffing, scraping, and DoS attacks.",
        attackScenario: "An attacker uses a botnet to make 10,000 login requests per second to your `/api/login` endpoint using leaked credentials from other data breaches. Without rate limiting, they can quickly find valid credentials and take over user accounts.",
        howToPrevent: [
            "Implement rate limiting on all public endpoints.",
            "Use different limits for different endpoints based on sensitivity.",
            "Apply rate limiting at the API gateway level.",
            "Return appropriate HTTP status codes (429) when limits are exceeded.",
            "Consider using IP-based and user-based rate limiting together."
        ]
    },
    {
        id: "sensitive-data-exposure",
        title: "Sensitive Data Exposure",
        category: "vulnerabilities",
        shortDescription: "APIs revealing sensitive data like passwords, tokens, PII, or internal system information.",
        longDescription: "Sensitive Data Exposure occurs when APIs inadvertently reveal sensitive information through error messages, overly verbose responses, missing data masking, or insecure data transmission. This includes passwords, API keys, personal information, financial data, and internal system details.",
        severity: "High",
        color: "from-red-500 to-rose-500",
        vulnerableCode: `//  VULNERABLE: Returning sensitive data in API responses
app.get("/api/users/:id", async (req, res) => {
    const user = await db.users.findById(req.params.id);
    
    // Returns ALL fields including password hash and internal IDs!
    res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        password: user.password_hash,  // Never expose this!
        ssn: user.ssn,  // PII should never be returned
        creditCard: user.credit_card,
        internalNotes: user.internal_notes
    });
});

// Error handler exposing system details
app.use((err, req, res, next) => {
    res.status(500).json({
        error: err.message,
        stack: err.stack,  // Exposes code paths!
        database: process.env.DB_NAME  // Secrets exposed!
    });
});`,
        secureCode: `//  SECURE: Filter sensitive data from responses
app.get("/api/users/:id", async (req, res) => {
    const user = await db.users.findById(req.params.id);
    
    // Only return public-facing fields
    res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        profilePicture: user.profile_picture
    });
});

// Secure error handler
app.use((err, req, res, next) => {
    // Log full error details server-side only
    logger.error("Server error", { 
        message: err.message, 
        stack: err.stack 
    });
    
    // Generic message to client
    res.status(500).json({
        error: "An unexpected error occurred"
    });
});`,
        explanation: "APIs often return more data than necessary, including sensitive fields like password hashes, credit card numbers, or PII. Attackers can exploit this by requesting user records and gathering sensitive information. Always filter response data and never expose internal system details in errors.",
        attackScenario: "A user requests their profile via `/api/user/me`. The API returns the full user object including their password hash (bcrypt). An attacker uses SQL injection to dump all user records, now having millions of password hashes to crack offline.",
        howToPrevent: [
            "Implement response filtering - only return necessary fields.",
            "Use DTOs (Data Transfer Objects) to control what's exposed.",
            "Never return password hashes or sensitive PII.",
            "Use generic error messages in production.",
            "Ensure all API traffic uses HTTPS."
        ]
    },

    // API Best Practices
    {
        id: "https-best-practice",
        title: "Use HTTPS for All Communications",
        category: "best-practices",
        shortDescription: "Encrypt all API communication to prevent interception, tampering, and man-in-the-middle attacks.",
        longDescription: "HTTPS (HTTP Secure) encrypts all communication between clients and servers using TLS (Transport Layer Security). Without HTTPS, all data is transmitted in plain text and can be intercepted, modified, or stolen by attackers on the network.",
        color: "from-green-500 to-emerald-600",
        explanation: "HTTPS provides three critical security properties: encryption (nobody can read the data), integrity (data cannot be tampered with), and authentication (you're communicating with the real server). Modern browsers now warn users about non-HTTPS sites.",
        bestPractices: [
            "Enable HTTPS on your web server and API endpoints.",
            "Use strong TLS configurations (TLS 1.2 or higher).",
            "Implement HTTP Strict Transport Security (HSTS) header.",
            "Use valid SSL/TLS certificates from trusted CAs.",
            "Redirect all HTTP traffic to HTTPS.",
            "Set the 'secure' flag on cookies."
        ]
    },
    {
        id: "input-validation",
        title: "Validate and Sanitize All Input",
        category: "best-practices",
        shortDescription: "All user input must be validated for type, format, length, and range before processing.",
        longDescription: "Input validation is the first line of defense against injection attacks. Every piece of data that comes from outside your system (request parameters, headers, body, cookies) must be validated before use. This includes type checking, format validation, length limits, and allowlist validation.",
        color: "from-blue-500 to-cyan-600",
        explanation: "Attackers use malicious input to inject code, bypass authentication, or crash your system. By validating all input, you reject invalid data before it ever reaches your business logic or database. Always validate on the server side - client-side validation can be bypassed.",
        bestPractices: [
            "Validate all input on the server side (never trust client validation).",
            "Use strict type checking (numbers, strings, booleans).",
            "Implement allowlist validation for known good values.",
            "Enforce minimum and maximum length limits.",
            "Validate formats (email, phone, date, etc.).",
            "Use schema validation libraries like Zod or Joi."
        ]
    },
    {
        id: "parameterized-queries",
        title: "Use Parameterized Queries",
        category: "best-practices",
        shortDescription: "Always use parameterized queries or prepared statements to prevent SQL injection.",
        longDescription: "Parameterized queries separate SQL code from user data, ensuring user input is always treated as data, not executable code. This is the most effective defense against SQL injection attacks.",
        color: "from-indigo-500 to-purple-600",
        explanation: "When you concatenate user input into SQL strings, attackers can escape the query and inject their own commands. Parameterized queries send the query structure and data separately, so malicious input becomes part of the data rather than part of the command.",
        bestPractices: [
            "Never concatenate user input directly into SQL strings.",
            "Use parameterized queries or prepared statements.",
            "Use ORMs that automatically use parameterized queries.",
            "Apply the same rule to NoSQL databases.",
            "Use stored procedures when appropriate."
        ]
    },
    {
        id: "least-privilege",
        title: "Apply Principle of Least Privilege",
        category: "best-practices",
        shortDescription: "Users and processes should have only the minimum permissions necessary to function.",
        longDescription: "The principle of least privilege means granting only the permissions absolutely necessary for a user, system, or process to complete its task. This limits the damage if an account is compromised, since attackers can only access what that account can access.",
        color: "from-teal-500 to-cyan-600",
        explanation: "If a service account has admin privileges and it's compromised, attackers gain full system access. By applying least privilege, even if an account is compromised, the attacker's access is limited to only what's necessary for that account's function.",
        bestPractices: [
            "Create separate service accounts with minimal permissions.",
            "Use role-based access control (RBAC).",
            "Implement API key scopes with limited permissions.",
            "Review and audit permissions regularly.",
            "Separate read and write permissions."
        ]
    },
    {
        id: "logging-best-practice",
        title: "Log Security Events Appropriately",
        category: "best-practices",
        shortDescription: "Log authentication attempts, access violations, and suspicious activities for security monitoring.",
        longDescription: "Security logging captures events relevant to detecting and investigating security incidents. This includes failed login attempts, unauthorized access attempts, unusual patterns, and system errors. Logs should be detailed enough for investigation but not expose sensitive data.",
        color: "from-slate-500 to-zinc-600",
        explanation: "Without security logging, you cannot detect attacks or investigate incidents. Proper logging provides visibility into what's happening in your system, enabling you to detect anomalies, respond to incidents, and comply with regulatory requirements.",
        bestPractices: [
            "Log all authentication events (success and failure).",
            "Log authorization failures and access violations.",
            "Log unusual patterns like rapid requests from one source.",
            "Include sufficient context (user, IP, timestamp, action).",
            "Never log sensitive data like passwords or tokens.",
            "Protect log integrity and implement log rotation."
        ]
    },

    // Authentication Methods
    {
        id: "oauth2",
        title: "OAuth 2.0 Implementation",
        category: "authentication",
        shortDescription: "Understanding OAuth 2.0 authorization framework for secure API access.",
        longDescription: "OAuth 2.0 is an authorization framework that enables applications to obtain limited access to user accounts on third-party services. It works by delegating user authentication to the service hosting the user account and authorizing third-party applications to access the user account.",
        color: "from-blue-600 to-indigo-700",
        explanation: "OAuth 2.0 allows users to grant third-party applications access to their resources without sharing passwords. It uses access tokens that can be limited in scope and time, providing better security than traditional API keys.",
        bestPractices: [
            "Use standard OAuth 2.0 flows appropriate for your use case.",
            "Validate redirect URIs strictly to prevent redirection attacks.",
            "Use short-lived access tokens with refresh tokens.",
            "Implement state parameter to prevent CSRF.",
            "Scope tokens to minimum required permissions.",
            "Use PKCE (Proof Key for Code Exchange) for public clients."
        ]
    },
    {
        id: "api-key-management",
        title: "API Key Management",
        category: "authentication",
        shortDescription: "Securely generate, store, rotate, and revoke API keys.",
        longDescription: "API keys are unique identifiers used to authenticate requests. They should be generated using cryptographically secure random values, stored securely, rotated regularly, and revocable in case of compromise.",
        color: "from-purple-600 to-fuchsia-600",
        explanation: "API keys provide a simple authentication mechanism but require proper management. Poor key management (hardcoding keys, never rotating them, not revoking compromised keys) leads to unauthorized access.",
        bestPractices: [
            "Generate keys using cryptographically secure random values.",
            "Store keys securely (environment variables, secrets managers).",
            "Never expose keys in URLs - use headers instead.",
            "Implement key expiration and rotation policies.",
            "Provide easy key revocation for security incidents.",
            "Use key scopes to limit permissions."
        ]
    },
    {
        id: "mfa",
        title: "Multi-Factor Authentication",
        category: "authentication",
        shortDescription: "Require multiple verification factors for added account security.",
        longDescription: "Multi-Factor Authentication (MFA) requires users to provide two or more verification factors: something they know (password), something they have (phone/token), and/or something they are (biometric). This significantly reduces the risk of unauthorized access.",
        color: "from-green-600 to-emerald-700",
        explanation: "Even if a password is compromised, attackers cannot access the account without the second factor. MFA is particularly important for administrative accounts and access to sensitive data.",
        bestPractices: [
            "Implement MFA for all administrative accounts.",
            "Support multiple MFA methods (TOTP, SMS, hardware tokens).",
            "Use authenticator apps over SMS when possible.",
            "Provide backup codes securely for account recovery.",
            "Consider risk-based authentication that prompts for MFA on suspicious activity."
        ]
    },
    {
        id: "session-management",
        title: "Session Management",
        category: "authentication",
        shortDescription: "Securely create, store, and invalidate user sessions.",
        longDescription: "Session management tracks user authentication state across requests. Secure session handling includes generating random session IDs, setting appropriate timeouts, protecting session cookies, and invalidating sessions on logout or inactivity.",
        color: "from-cyan-600 to-sky-700",
        explanation: "Weak session management allows session hijacking, session fixation, and unauthorized access. Attackers who steal or guess session IDs can impersonate legitimate users.",
        bestPractices: [
            "Generate session IDs using cryptographically secure random values.",
            "Set appropriate session timeouts (shorter for sensitive actions).",
            "Regenerate session IDs after authentication.",
            "Mark session cookies as Secure, HttpOnly, and SameSite.",
            "Implement server-side session invalidation.",
            "Detect and handle concurrent session logins appropriately."
        ]
    },

    // Data Protection
    {
        id: "encryption-at-rest",
        title: "Data Encryption at Rest",
        category: "data-protection",
        shortDescription: "Encrypt stored data to protect against physical theft and unauthorized access.",
        longDescription: "Encryption at rest protects stored data (in databases, file systems, backups) by encrypting it so that unauthorized parties cannot read it even if they gain physical or logical access to the storage medium.",
        color: "from-slate-600 to-zinc-700",
        explanation: "Data at rest is vulnerable to physical theft, media reuse attacks, and unauthorized database access. Encryption ensures that even if attackers obtain the storage media, they cannot read the data without the encryption keys.",
        bestPractices: [
            "Use database-level encryption (TDE) for sensitive fields.",
            "Encrypt file systems and backups.",
            "Store encryption keys separately from encrypted data.",
            "Use strong encryption algorithms (AES-256).",
            "Implement proper key management and rotation."
        ]
    },
    {
        id: "encryption-in-transit",
        title: "Data Encryption in Transit",
        category: "data-protection",
        shortDescription: "Encrypt all network communication to prevent interception and tampering.",
        longDescription: "Encryption in transit protects data as it travels between clients, servers, and between microservices. This prevents man-in-the-middle attacks, eavesdropping, and data tampering during transmission.",
        color: "from-slate-700 to-neutral-700",
        explanation: "Without encryption in transit, anyone on the network path can intercept, read, or modify data. This is especially important for sensitive data like credentials, personal information, and financial data.",
        bestPractices: [
            "Use TLS 1.2 or higher for all connections.",
            "Configure strong cipher suites.",
            "Use valid certificates from trusted CAs.",
            "Implement certificate pinning for mobile apps.",
            "Set HSTS header to enforce HTTPS."
        ]
    },
    {
        id: "pii-handling",
        title: "PII Data Handling",
        category: "data-protection",
        shortDescription: "Properly collect, process, store, and dispose of Personally Identifiable Information.",
        longDescription: "Personally Identifiable Information (PII) includes any data that can identify an individual (name, email, SSN, phone, address). Handling PII requires compliance with privacy regulations and implementing appropriate security controls.",
        color: "from-amber-600 to-orange-700",
        explanation: "PII is a prime target for attackers and subject to strict regulatory requirements (GDPR, CCPA, HIPAA). Mishandling PII leads to identity theft, regulatory fines, and reputational damage.",
        bestPractices: [
            "Minimize PII collection - only collect what's necessary.",
            "Implement data anonymization and pseudonymization.",
            "Obtain proper consent for data collection.",
            "Provide data subject access and deletion rights.",
            "Encrypt PII both in transit and at rest.",
            "Retain PII only as long as necessary."
        ]
    },
    {
        id: "data-retention",
        title: "Data Retention Policies",
        category: "data-protection",
        shortDescription: "Define and enforce how long data is kept and when it should be deleted.",
        longDescription: "Data retention policies define how long different types of data are kept. Retaining data longer than necessary increases risk, storage costs, and regulatory exposure. Proper policies ensure data is deleted when no longer needed.",
        color: "from-stone-600 to-neutral-700",
        explanation: "Old data is a liability. If a breach occurs, less data means less damage. Regulatory frameworks often require specific retention periods, and holding data longer than necessary can result in fines.",
        bestPractices: [
            "Define retention periods for each data type.",
            "Automate data deletion on schedule.",
            "Implement secure data deletion (cryptographic erasure).",
            "Maintain audit logs of data retention and deletion.",
            "Review and update retention policies regularly."
        ]
    }
];

export const getKnowledgeItemsByCategory = (category: string): KnowledgeItem[] => {
    return knowledgeItems.filter(item => item.category === category);
};

export const getKnowledgeItemById = (id: string): KnowledgeItem | undefined => {
    return knowledgeItems.find(item => item.id === id);
};

export const knowledgeCategoriesList = [
    { id: "owasp", name: "OWASP API Security Top 10", description: "The most critical API security risks" },
    { id: "vulnerabilities", name: "Common Vulnerability Types", description: "Learn about common security vulnerabilities" },
    { id: "best-practices", name: "API Best Practices", description: "Secure coding practices for APIs" },
    { id: "authentication", name: "Authentication Methods", description: "Understanding API authentication" },
    { id: "data-protection", name: "Data Protection", description: "Protecting sensitive data" }
];
