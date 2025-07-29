use actix_web::{web, App, HttpServer, Responder, HttpResponse, Result as ActixResult};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{query, query_as, Row};
use dotenv::dotenv;
use std::env;
use std::collections::HashMap;
use tera::{Tera, Context};

// To add the database pool to the application context
struct AppState {
    db_pool: SqlitePool,
    tera: Tera,
}

#[derive(Deserialize, Debug)]
struct SearchQuery {
    query: String,
}

#[derive(Deserialize, Debug)]
struct FeedbackForm {
    name: String,
    email: String, // XSS
    message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Product {
    id: i64,
    name: String,
    price: f64,
    stock: i64,
}

#[derive(Deserialize, Debug)]
struct OrderRequest {
    product_id: i64,
    quantity: i64,
}

#[derive(Serialize, Deserialize, Debug)]
struct User {
    username: String,
    role: String, // role for privilege
}

// Endpoint: /search
// Description: The ‘query’ parameter received from the user is added directly to the SQL query.
// Attack Example: ‘ OR '1’='1 --
async fn search_products(
    app_state: web::Data<AppState>,
    query_params: web::Query<SearchQuery>,
) -> ActixResult<HttpResponse> {
    let sql_query = format!(
        "SELECT id, name, price, stock FROM products WHERE name LIKE '%{}%'",
        query_params.query
    );

    println!("SQL Sorgusu: {}", sql_query); // Debug için

    let products: Vec<Product> = query_as::<_, Product>(&sql_query)
        .fetch_all(&app_state.db_pool)
        .await
        .map_err(|e| {
            eprintln!("SQL hatası: {}", e);
            actix_web::error::ErrorInternalServerError("Veritabanı hatası")
        })?;

    Ok(HttpResponse::Ok().json(products))
}

// Endpoint: /feedback
// Description: The ‘email’ parameter received from the user is printed directly to the HTML output.
// Attack Example: <script>alert('affinidi');</script>
async fn submit_feedback(
    app_state: web::Data<AppState>,
    form: web::Form<FeedbackForm>,
) -> ActixResult<HttpResponse> {
    let mut context = Context::new();
    context.insert("name", &form.name);
    context.insert("email", &form.email); // unsafe usage
    context.insert("message", &form.message);

    let rendered = app_state.tera.render("feedback_result.html", &context)
        .map_err(|e| {
            eprintln!("Template render hatası: {}", e);
            actix_web::error::ErrorInternalServerError("Sunucu hatası")
        })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

// Endpoint: /check_status
// Description: The server makes a request to the URL provided by the user.
// Attack Example: ?url=http://localhost:8080/admin_internal_api or ?url=file:///etc/passwd
async fn check_status(
    query_params: web::Query<HashMap<String, String>>,
) -> ActixResult<HttpResponse> {
    let target_url = query_params.get("url").cloned().unwrap_or_else(|| {
        env::var("SSRF_TARGET_URL").unwrap_or_else(|_| "http://localhost:8080".to_string())
    });

    println!("SSRF Hedefi: {}", target_url);

    match reqwest::get(&target_url).await {
        Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_else(|_| "Yanıt okunamadı".to_string());
            Ok(HttpResponse::Ok().body(format!("Durum: {}\nYanıt: {}", status, body)))
        }
        Err(e) => {
            eprintln!("SSRF hatası: {}", e);
            Ok(HttpResponse::InternalServerError().body(format!("SSRF Hatası: {}", e)))
        }
    }
}

// ssrf - api
async fn admin_internal_api() -> impl Responder {
    HttpResponse::Ok().body("Dahili Yönetim API'si: Sadece localhost'tan erişilmeli.")
}

// ssrf 
async fn internal_status() -> impl Responder {
    HttpResponse::Ok().body("Uygulama durumu: Sağlıklı (Sadece dahili kullanım için)")
}


// Endpoint: /order
// Description: The user can increase the product stock by placing an order with a negative quantity.
// Attack Example: {“product_id”: 1, “quantity”: -100}
async fn create_order(
    app_state: web::Data<AppState>,
    order_req: web::Json<OrderRequest>,
) -> ActixResult<HttpResponse> {
    let product_id = order_req.product_id;
    let quantity = order_req.quantity;

    // Negative quantity checks are not performed!
    // This causes the stock to increase when the operation `stock = stock - quantity` is performed with a negative number.
    let result = query!(
        "UPDATE products SET stock = stock - ? WHERE id = ?",
        quantity, // Kasıtlı olarak negatif kontrolü yok
        product_id
    )
    .execute(&app_state.db_pool)
    .await;

    match result {
        Ok(res) if res.rows_affected() > 0 => {
            Ok(HttpResponse::Ok().body(format!("Sipariş oluşturuldu. Ürün ID: {}, Miktar: {}", product_id, quantity)))
        }
        Ok(_) => Ok(HttpResponse::NotFound().body("Ürün bulunamadı veya stok güncellenemedi.")),
        Err(e) => {
            eprintln!("Sipariş hatası: {}", e);
            ActixResult::Err(actix_web::error::ErrorInternalServerError("Sipariş verilirken hata oluştu"))
        }
    }
}

// Endpoint: /checkout
// Explanation: No payment is taken for products with a price of 0 or negative, but the order is still completed.
// Attack Example: Create a product with price=0 or price=-1 in the database and purchase it.
async fn checkout(
    app_state: web::Data<AppState>,
    order_req: web::Json<OrderRequest>,
) -> ActixResult<HttpResponse> {
    let product_id = order_req.product_id;
    let quantity = order_req.quantity;

    // get product from db
    let product: Product = query_as!(Product, "SELECT id, name, price, stock FROM products WHERE id = ?", product_id)
        .fetch_one(&app_state.db_pool)
        .await
        .map_err(|e| {
            eprintln!("Checkout hatası: Ürün bulunamadı veya veritabanı hatası: {}", e);
            actix_web::error::ErrorNotFound("Ürün bulunamadı")
        })?;


    // logic error: If the price is 0 or negative, no money is actually received, but the transaction is completed.
    if product.price <= 0.0 {
        // normally it should be throw error.
        return Ok(HttpResponse::Ok().body(format!("Checkout başarılı! Ancak ürün '{}' için fiyat ödenmedi (Fiyat: {}).", product.name, product.price)));
    }

    if product.stock < quantity {
        return Ok(HttpResponse::BadRequest().body("Yetersiz stok."));
    }

    // logic error to decrease
    let update_result = query!(
        "UPDATE products SET stock = stock - ? WHERE id = ?",
        quantity,
        product_id
    )
    .execute(&app_state.db_pool)
    .await;

    match update_result {
        Ok(res) if res.rows_affected() > 0 => {
            // payment integration normally.
            // skip payment integration to intentionally have bug on payment
            Ok(HttpResponse::Ok().body(format!("Checkout başarılı! Ürün '{}' satın alındı. Miktar: {}", product.name, quantity)))
        }
        Ok(_) => Ok(HttpResponse::InternalServerError().body("Stok güncellenemedi, lütfen tekrar deneyin.")),
        Err(e) => {
            eprintln!("Checkout sırasında stok güncelleme hatası: {}", e);
            ActixResult::Err(actix_web::error::ErrorInternalServerError("Checkout hatası"))
        }
    }
}


// --- main func ---
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok(); // .env load

    // db connection
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite::memory:".to_string());
    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("Veritabanı bağlantısı kurulamadı!");

    // db schema
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Veritabanı migrasyonu başarısız oldu!");

    // Tera template engine'ı hazırla (XSS için)
    let mut tera = Tera::new("templates/**/*").expect("Tera templates yüklenemedi");
    tera.auto_escape_on(false); // XSS için oto-escape'i kapatıyoruz!

    let app_state = web::Data::new(AppState { db_pool: pool.clone(), tera });

    println!("Uygulama çalışıyor: http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(web::resource("/").to(|| async {
                HttpResponse::Ok().body("Zafiyetli Rust Uygulamasına Hoş Geldiniz!\n\nEndpointler:\n/search?query=<sorgu>\n/feedback (POST)\n/check_status?url=<url>\n/order (POST)\n/checkout (POST)\n/admin_internal_api (SSRF hedefi)\n/internal_status (SSRF hedefi)")
            }))
            .service(web::resource("/search").to(search_products))
            .service(web::resource("/feedback").route(web::post().to(submit_feedback)))
            .service(web::resource("/check_status").to(check_status))
            .service(web::resource("/order").route(web::post().to(create_order)))
            .service(web::resource("/checkout").route(web::post().to(checkout)))
            .service(web::resource("/admin_internal_api").to(admin_internal_api)) // SSRF can reach it out ONLY, in theory :D 
            .service(web::resource("/internal_status").to(internal_status)) // SSRF can reach it out ONLY, in theory :D 
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}