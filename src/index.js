const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Setup-Key",
  "Content-Type": "application/json; charset=utf-8"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders
  });
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function randomHex(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(data, b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

async function hashPassword(password, salt = randomHex(16)) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  const hash = Array.from(new Uint8Array(bits), b =>
    b.toString(16).padStart(2, "0")
  ).join("");

  return `${salt}:${hash}`;
}

async function verifyPassword(password, stored) {
  const [salt, expected] = (stored || "").split(":");

  if (!salt || !expected) return false;

  const actual = await hashPassword(password, salt);
  return actual === `${salt}:${expected}`;
}

async function requireCashier(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return { error: json({ success: false, message: "Silakan login sebagai kasir" }, 401) };
  }

  const tokenHash = await sha256(match[1]);

  const cashier = await env.DB.prepare(`
    SELECT c.id, c.username
    FROM cashier_sessions s
    JOIN cashiers c ON c.id = s.cashier_id
    WHERE s.token_hash = ?
      AND datetime(s.expires_at) > datetime('now')
      AND c.is_active = 1
  `).bind(tokenHash).first();

  if (!cashier) {
    return { error: json({ success: false, message: "Sesi tidak valid atau sudah berakhir" }, 401) };
  }

  return { cashier };
}

function validProduct(body) {
  return body &&
    typeof body.name === "string" &&
    body.name.trim().length > 0 &&
    body.name.trim().length <= 150 &&
    Number.isSafeInteger(body.price) &&
    body.price >= 0 &&
    Number.isSafeInteger(body.stock) &&
    body.stock >= 0 &&
    body.stock <= 1000000 &&
    (body.description == null || typeof body.description === "string") &&
    (body.category == null || typeof body.category === "string") &&
    (body.image_url == null || typeof body.image_url === "string");
}

function productValues(body) {
  return {
    name: body.name.trim(),
    description: body.description || "",
    price: body.price,
    image_url: body.image_url || "",
    category: body.category || "",
    stock: body.stock
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      // Cek koneksi backend dan database
      if (path === "/api/health" && method === "GET") {
        await env.DB.prepare("SELECT 1").first();

        return json({
          success: true,
          message: "Cake Order API aktif",
          database: "connected"
        });
      }

      // Buat kasir pertama. Memerlukan secret Cloudflare.
      if (path === "/api/auth/setup" && method === "POST") {
        if (!env.CASHIER_SETUP_KEY) {
          return json({
            success: false,
            message: "Secret CASHIER_SETUP_KEY belum diatur"
          }, 500);
        }

        if (request.headers.get("X-Setup-Key") !== env.CASHIER_SETUP_KEY) {
          return json({ success: false, message: "Kunci setup salah" }, 403);
        }

        const body = await readJson(request);

        if (
          !body ||
          typeof body.username !== "string" ||
          !/^[a-zA-Z0-9_.-]{3,40}$/.test(body.username) ||
          typeof body.password !== "string" ||
          body.password.length < 12 ||
          body.password.length > 128
        ) {
          return json({
            success: false,
            message: "Username harus 3–40 karakter dan password 12–128 karakter"
          }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM cashiers"
        ).first();

        if (existing.total > 0) {
          return json({
            success: false,
            message: "Akun kasir pertama sudah dibuat"
          }, 409);
        }

        const passwordHash = await hashPassword(body.password);

        // Kondisi jumlah kasir diperiksa lagi dalam perintah INSERT.
        // Gunakan hanya untuk setup awal; jangan publikasikan kunci setup.
        const result = await env.DB.prepare(`
          INSERT INTO cashiers (username, password_hash)
          SELECT ?, ?
          WHERE NOT EXISTS (SELECT 1 FROM cashiers)
        `).bind(body.username, passwordHash).run();

        if (!result.meta.changes) {
          return json({
            success: false,
            message: "Akun kasir sudah dibuat"
          }, 409);
        }

        return json({
          success: true,
          message: "Akun kasir pertama berhasil dibuat"
        }, 201);
      }

      // Login kasir
      if (path === "/api/auth/login" && method === "POST") {
        const body = await readJson(request);

        if (
          !body ||
          typeof body.username !== "string" ||
          typeof body.password !== "string"
        ) {
          return json({
            success: false,
            message: "Username dan password wajib diisi"
          }, 400);
        }

        const cashier = await env.DB.prepare(`
          SELECT id, username, password_hash
          FROM cashiers
          WHERE username = ? AND is_active = 1
        `).bind(body.username).first();

        if (!cashier || !(await verifyPassword(body.password, cashier.password_hash))) {
          return json({
            success: false,
            message: "Username atau password salah"
          }, 401);
        }

        const token = randomHex(32);
        const tokenHash = await sha256(token);
        const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();

        await env.DB.prepare(`
          INSERT INTO cashier_sessions (cashier_id, token_hash, expires_at)
          VALUES (?, ?, ?)
        `).bind(cashier.id, tokenHash, expiresAt).run();

        return json({
          success: true,
          message: "Login berhasil",
          token,
          expiresAt,
          cashier: {
            id: cashier.id,
            username: cashier.username
          }
        });
      }

      // Logout kasir
      if (path === "/api/auth/logout" && method === "POST") {
        const authorization = request.headers.get("Authorization") || "";
        const match = authorization.match(/^Bearer\s+(.+)$/i);

        if (!match) {
          return json({ success: false, message: "Token tidak ditemukan" }, 401);
        }

        await env.DB.prepare(
          "DELETE FROM cashier_sessions WHERE token_hash = ?"
        ).bind(await sha256(match[1])).run();

        return json({ success: true, message: "Logout berhasil" });
      }

      // Katalog publik: hanya produk aktif
      if (path === "/api/products" && method === "GET") {
        const result = await env.DB.prepare(`
          SELECT id, name, description, price, image_url, category, stock
          FROM products
          WHERE is_active = 1
          ORDER BY id DESC
        `).all();

        return json({ success: true, data: result.results });
      }

      // Detail produk publik
      const publicProductMatch = path.match(/^\/api\/products\/(\d+)$/);

      if (publicProductMatch && method === "GET") {
        const product = await env.DB.prepare(`
          SELECT id, name, description, price, image_url, category, stock
          FROM products
          WHERE id = ? AND is_active = 1
        `).bind(Number(publicProductMatch[1])).first();

        if (!product) {
          return json({ success: false, message: "Produk tidak ditemukan" }, 404);
        }

        return json({ success: true, data: product });
      }

      // Semua endpoint katalog kasir di bawah ini memerlukan login
      if (path.startsWith("/api/cashier/products")) {
        const auth = await requireCashier(request, env);
        if (auth.error) return auth.error;

        // Daftar semua produk, termasuk yang nonaktif
        if (path === "/api/cashier/products" && method === "GET") {
          const result = await env.DB.prepare(`
            SELECT id, name, description, price, image_url, category,
                   stock, is_active, created_at, updated_at
            FROM products
            ORDER BY id DESC
          `).all();

          return json({ success: true, data: result.results });
        }

        // Tambah produk
        if (path === "/api/cashier/products" && method === "POST") {
          const body = await readJson(request);

          if (!validProduct(body)) {
            return json({
              success: false,
              message: "Data produk tidak valid. Periksa nama, harga, dan stok."
            }, 400);
          }

          const p = productValues(body);

          const result = await env.DB.prepare(`
            INSERT INTO products
              (name, description, price, image_url, category, stock, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
          `).bind(
            p.name, p.description, p.price,
            p.image_url, p.category, p.stock
          ).run();

          return json({
            success: true,
            message: "Produk berhasil ditambahkan",
            id: result.meta.last_row_id
          }, 201);
        }

        const productMatch = path.match(/^\/api\/cashier\/products\/(\d+)$/);

        if (productMatch) {
          const id = Number(productMatch[1]);

          // Edit produk
          if (method === "PUT") {
            const body = await readJson(request);

            if (!validProduct(body)) {
              return json({
                success: false,
                message: "Data produk tidak valid. Periksa nama, harga, dan stok."
              }, 400);
            }

            const p = productValues(body);

            const result = await env.DB.prepare(`
              UPDATE products
              SET name = ?, description = ?, price = ?, image_url = ?,
                  category = ?, stock = ?, updated_at = datetime('now')
              WHERE id = ?
            `).bind(
              p.name, p.description, p.price,
              p.image_url, p.category, p.stock, id
            ).run();

            if (!result.meta.changes) {
              return json({ success: false, message: "Produk tidak ditemukan" }, 404);
            }

            return json({ success: true, message: "Produk berhasil diperbarui" });
          }

          // Aktifkan/nonaktifkan produk
          if (method === "PATCH") {
            const body = await readJson(request);

            if (!body || ![0, 1].includes(body.is_active)) {
              return json({
                success: false,
                message: "is_active harus bernilai 1 (aktif) atau 0 (nonaktif)"
              }, 400);
            }

            const result = await env.DB.prepare(`
              UPDATE products
              SET is_active = ?, updated_at = datetime('now')
              WHERE id = ?
            `).bind(body.is_active, id).run();

            if (!result.meta.changes) {
              return json({ success: false, message: "Produk tidak ditemukan" }, 404);
            }

            return json({
              success: true,
              message: body.is_active ? "Produk diaktifkan" : "Produk dinonaktifkan"
            });
          }

          // Hapus permanen jika belum dipakai di riwayat pesanan
          if (method === "DELETE") {
            const used = await env.DB.prepare(`
              SELECT 1 FROM order_items WHERE product_id = ? LIMIT 1
            `).bind(id).first();

            if (used) {
              return json({
                success: false,
                message: "Produk sudah ada di riwayat pesanan. Nonaktifkan produk sebagai gantinya."
              }, 409);
            }

            const result = await env.DB.prepare(
              "DELETE FROM products WHERE id = ?"
            ).bind(id).run();

            if (!result.meta.changes) {
              return json({ success: false, message: "Produk tidak ditemukan" }, 404);
            }

            return json({ success: true, message: "Produk berhasil dihapus" });
          }
        }
      }

      return json({
        success: false,
        message: "Endpoint tidak ditemukan"
      }, 404);
    } catch (error) {
      console.error("API error:", error);

      return json({
        success: false,
        message: "Terjadi kesalahan pada server. Periksa log Worker."
      }, 500);
    }
  }
};
