# Vulnerable Rust Web Application (For Security Scanner Testing)

This project is a deliberately vulnerable Rust web application designed to help test the efficacy of security scanners (SAST, DAST, IAST) in detecting common web application vulnerabilities.

**WARNING:** This application contains known security vulnerabilities and MUST NOT be deployed in a production environment. It is intended solely for security testing and educational purposes.

---

## Setup and Execution

Follow these steps to set up and run the application locally:

1.  **Initialize the Project:**
    If you haven't already, create a new Rust project and navigate into its directory:
    ```bash
    cargo new vulnerable_rust_app
    cd vulnerable_rust_app
    ```

2.  **Update `Cargo.toml`:**
    Replace the contents of your `Cargo.toml` file with the following dependencies:

    ```toml
    [package]
    name = "vulnerable_rust_app"
    version = "0.1.0"
    edition = "2021"

    [dependencies]
    actix-web = "4"
    tokio = { version = "1", features = ["full"] }
    serde = { version = "1.0", features = ["derive"] }
    serde_json = "1.0"
    sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "sqlite"] } # SQLite support
    dotenv = "0.15"
    reqwest = { version = "0.11", features = ["json"] } # For SSRF
    tera = "1.19" # For XSS template rendering
    ```

3.  **Create/Update `src/main.rs`:**
    Populate `src/main.rs` with the application code provided previously. This file contains the implementations of all the vulnerabilities.

4.  **Create Database Migrations:**
    In the root directory of your project, create a folder named `migrations`. Inside this folder, create a file named `20231027100000_initial_schema.sql` (the naming convention is `YYYYMMDDHHMMSS_name.sql`). Add the following SQL content to this file:

    ```sql
    -- migration.sql
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        stock INTEGER NOT NULL
    );

    -- Insert sample data
    INSERT INTO products (name, price, stock) VALUES ('Laptop', 1200.0, 50);
    INSERT INTO products (name, price, stock) VALUES ('Mouse', 25.0, 200);
    INSERT INTO products (name, price, stock) VALUES ('Keyboard', 75.0, 100);
    INSERT INTO products (name, price, stock) VALUES ('Monitor', 300.0, 30);
    INSERT INTO products (name, price, stock) VALUES ('Zero Price Item', 0.0, 10);     -- For Logic Bug 2
    INSERT INTO products (name, price, stock) VALUES ('Negative Price Item', -10.0, 5); -- For Logic Bug 2
    ```

5.  **Create Template File:**
    In the root directory of your project, create a folder named `templates`. Inside this folder, create a file named `feedback_result.html` and add the following HTML content:

    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Your Feedback</title>
        <style>
            body { font-family: sans-serif; margin: 20px; }
            .container { border: 1px solid #ccc; padding: 20px; border-radius: 8px; }
            h1 { color: #333; }
            p { margin-bottom: 10px; }
            strong { color: #555; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Your Feedback Has Been Received!</h1>
            <p><strong>Name:</strong> {{ name }}</p>
            <p><strong>Email:</strong> {{ email }}</p> {# XSS Vulnerability Here! #}
            <p><strong>Message:</strong> {{ message }}</p>
            <p>Thank you!</p>
            <a href="/">Home</a>
        </div>
    </body>
    </html>
    ```

6.  **Create `.env` File:**
    In the root directory of your project, create a file named `.env` and add the following line (used for SSRF testing):

    ```
    SSRF_TARGET_URL=http://localhost:8080/internal_status
    ```

7.  **Run the Application:**
    Once all files are correctly placed, run the application from your project's root directory:
    ```bash
    cargo run
    ```
    The application will be accessible at `http://127.0.0.1:8080` by default.

---

## Identified Security Vulnerabilities

This section details the deliberate security vulnerabilities within the application and provides methods to test them.

### 1. SQL Injection

* **Vulnerability Type:** Injection
* **Endpoint:** `/search` (GET request)
* **Description:** The `query` parameter received from the user is directly concatenated into the SQL query without proper sanitization or parameterization. This allows malicious actors to alter the SQL statement, leading to unauthorized data access or manipulation.
* **Location:** `src/main.rs`, `search_products` function.
    * **Relevant Code Line:** `let sql_query = format!("SELECT id, name, price, stock FROM products WHERE name LIKE '%{}%'", query_params.query);`
* **Test Cases:**
    * **Retrieve All Products (Boolean-based):** `http://127.0.0.1:8080/search?query=%27%20OR%20%271%27%3D%271`
        * URL decoded: `query=' OR '1'='1`
    * **Using Comments:** `http://127.0.0.1:8080/search?query=Mouse%27%20OR%201%3D1%20--`
        * URL decoded: `query=Mouse' OR 1=1 --`
    * **Expected Result:** Both cases should return all products from the database.

---

### 2. Cross-Site Scripting (XSS)

* **Vulnerability Type:** Client-Side Injection (XSS)
* **Endpoint:** `/feedback` (POST request)
* **Description:** The `email` field from the feedback form is directly rendered into the `feedback_result.html` template without any HTML escaping. This enables attackers to inject arbitrary JavaScript code that executes in the victim's browser.
* **Location:** `src/main.rs`, `submit_feedback` function and `templates/feedback_result.html`. The `main` function explicitly disables auto-escaping for `tera`.
    * **Relevant Code Lines:**
        * `src/main.rs`: `app_state.tera.auto_escape_on(false);`
        * `templates/feedback_result.html`: `<p><strong>Email:</strong> {{ email }}</p>`
* **Test Cases:**
    * Using a POST request tool (e.g., Postman, Insomnia, or browser developer tools), send the following JSON payload to `/feedback`:
        ```json
        {
            "name": "Test User",
            "email": "<script>alert('XSS Successful!');</script>",
            "message": "This is an XSS test."
        }
        ```
    * **Expected Result:** An `alert` pop-up should appear in the browser when viewing the response HTML.

---

### 3. Server-Side Request Forgery (SSRF)

* **Vulnerability Type:** Server-Side Request Forgery (SSRF)
* **Endpoint:** `/check_status` (GET request)
* **Description:** The server makes an HTTP request to a URL provided by the user via the `url` parameter. There is no input validation or URL restriction (whitelist/blacklist), allowing an attacker to force the server to make requests to internal network services or access sensitive files using protocols like `file:///`.
* **Location:** `src/main.rs`, `check_status` function.
    * **Relevant Code Line:** `match reqwest::get(&target_url).await { ... }`
* **Test Cases:**
    * **Access Internal Endpoints:**
        * `http://127.0.0.1:8080/check_status?url=http://localhost:8080/admin_internal_api`
        * `http://127.0.0.1:8080/check_status?url=http://localhost:8080/internal_status`
    * **Local File Inclusion (file:// protocol):**
        * On Linux/macOS: `http://127.0.0.1:8080/check_status?url=file:///etc/passwd`
        * On Windows: `http://127.0.0.1:8080/check_status?url=file:///C:/Windows/System32/drivers/etc/hosts`
    * **Expected Result:** The server's response should include the content from the internal endpoints or system files.

---

### 4. Logic Bug 1: Stock Increase with Negative Quantity

* **Vulnerability Type:** Business Logic Error
* **Endpoint:** `/order` (POST request)
* **Description:** The `create_order` function lacks validation for negative values in the `quantity` parameter. Since stock is updated using `stock = stock - ?`, providing a negative quantity will effectively increase the stock (`stock - (-10) = stock + 10`). This can lead to inventory manipulation and financial discrepancies.
* **Location:** `src/main.rs`, `create_order` function.
    * **Relevant Code Line:** `query!("UPDATE products SET stock = stock - ? WHERE id = ?", quantity, product_id)`
* **Test Cases:**
    1.  First, check the current stock of a product (e.g., "Laptop" with ID 1) using `http://127.0.0.1:8080/search?query=Laptop`. Assume initial stock is 50.
    2.  Send the following JSON payload to `/order`:
        ```json
        {
            "product_id": 1,
            "quantity": -10
        }
        ```
    3.  Verify the stock again using `/search?query=Laptop`.
    * **Expected Result:** The stock should have increased from 50 to 60.

---

### 5. Logic Bug 2: Purchasing Zero/Negative Priced Items

* **Vulnerability Type:** Business Logic Error
* **Endpoint:** `/checkout` (POST request)
* **Description:** The `checkout` function allows transactions to complete successfully even when the product's price is zero or negative. The payment mechanism is entirely bypassed, enabling attackers to "purchase" items for free or even profit from items with negative prices.
* **Location:** `src/main.rs`, `checkout` function.
    * **Relevant Code Line:** `if product.price <= 0.0 { ... return Ok(HttpResponse::Ok().body(format!("Checkout successful! However, no price was paid for product '{}' (Price: {}).", product.name, product.price))); }`
* **Test Cases:**
    * The database migration includes products with zero and negative prices: 'Zero Price Item' (ID: 5) and 'Negative Price Item' (ID: 6).
    * Send one of the following JSON payloads to `/checkout`:
        * **Purchase Zero-Priced Item:**
            ```json
            {
                "product_id": 5,
                "quantity": 1
            }
            ```
        * **Purchase Negative-Priced Item:**
            ```json
            {
                "product_id": 6,
                "quantity": 1
            }
            ```
    * **Expected Result:** The response will indicate "Checkout successful! However, no price was paid..." despite no actual payment processing.

---
