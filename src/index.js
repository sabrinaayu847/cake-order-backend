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
    return {
      error: json({
        success: false,
        message: "Silakan login sebagai kasir"
      }, 401)
    };
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
    return {
      error: json({
        success: false,
        message: "Sesi tidak valid atau sudah berakhir"
      }, 401)
    };
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
    (body.description == null ||
      typeof body.description === "string") &&
    (body.category == null ||
      typeof body.category === "string") &&
    (body.image_url == null ||
      typeof body.image_url === "string") &&
    (body.image_data == null ||
      (typeof body.image_data === "string" &&
       body.image_data.length <= 1500000));
}

function productValues(body) {
  return {
    name: body.name.trim(),
    description: body.description || "",
    price: body.price,
    image_url: body.image_url || "",
    image_data: body.image_data || "",
    category: body.category || "",
    stock: body.stock
  };
}

function makeOrderCode() {
  return "CK-" + Date.now().toString(36).toUpperCase() +
    "-" + randomHex(3).toUpperCase();
}

function validCustomer(body) {
  return body &&
    typeof body.customer_name === "string" &&
    body.customer_name.trim().length >= 2 &&
    body.customer_name.trim().length <= 100 &&
    typeof body.customer_phone === "string" &&
    body.customer_phone.trim().length >= 8 &&
    body.customer_phone.trim().length <= 25 &&
    typeof body.customer_address === "string" &&
    body.customer_address.trim().length >= 3 &&
    body.customer_address.trim().length <= 500 &&
    (body.customer_note == null ||
      (typeof body.customer_note === "string" &&
       body.customer_note.length <= 1000)) &&
    Array.isArray(body.items) &&
    body.items.length >= 1 &&
    body.items.length <= 50 &&
    body.items.every(item =>
      item &&
      Number.isSafeInteger(Number(item.product_id)) &&
      Number(item.product_id) > 0 &&
      Number.isSafeInteger(Number(item.quantity)) &&
      Number(item.quantity) >= 1 &&
      Number(item.quantity) <= 1000
    );
}

async function getCustomerOrder(request, env, code) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return {
      error: json({
        success: false,
        message: "Token akses pesanan diperlukan"
      }, 401)
    };
  }

  const tokenHash = await sha256(match[1]);

  const order = await env.DB.prepare(`
    SELECT id, order_code, customer_name, customer_phone,
           customer_address, customer_note, total_amount,
           order_status, payment_status, rejection_reason,
           created_at, updated_at
    FROM orders
    WHERE order_code = ? AND access_token_hash = ?
  `).bind(code, tokenHash).first();

  if (!order) {
    return {
      error: json({
        success: false,
        message: "Pesanan tidak ditemukan atau token tidak valid"
      }, 404)
    };
  }

  return { order };
}

async function cancelOrderAndRestoreStock(env, {
  orderId,
  allowedStatuses,
  paymentStatus,
  rejectionReason,
  cashierId
}) {
  const order = await env.DB.prepare(`
    SELECT id, order_status, payment_status, stock_restored_at
    FROM orders
    WHERE id = ?
  `).bind(orderId).first();

  if (!order) {
    return {
      ok: false,
      status: 404,
      message: "Pesanan tidak ditemukan"
    };
  }

  if (order.stock_restored_at != null) {
    return {
      ok: false,
      status: 409,
      message: "Stok pesanan sudah pernah dikembalikan"
    };
  }

  const allowed = allowedStatuses.some(
    status =>
      order.order_status === status.order_status &&
      order.payment_status === status.payment_status
  );

  if (!allowed) {
    return {
      ok: false,
      status: 409,
      message: "Pesanan sudah diproses atau tidak dapat dibatalkan"
    };
  }

  const itemsResult = await env.DB.prepare(`
    SELECT product_id, quantity
    FROM order_items
    WHERE order_id = ?
  `).bind(orderId).all();

  const restoreKey = `${Date.now()}-${randomHex(16)}`;

  const updateOrder = env.DB.prepare(`
    UPDATE orders
    SET order_status = 'cancelled',
        payment_status = COALESCE(?, payment_status),
        rejection_reason = COALESCE(?, rejection_reason),
        verified_by_cashier_id = COALESCE(?, verified_by_cashier_id),
        verified_at = CASE
          WHEN ? IS NOT NULL THEN datetime('now')
          ELSE verified_at
        END,
        stock_restored_at = ?,
        updated_at = datetime('now')
    WHERE id = ?
      AND stock_restored_at IS NULL
      AND order_status = ?
      AND payment_status = ?
  `).bind(
    paymentStatus ?? null,
    rejectionReason ?? null,
    cashierId ?? null,
    rejectionReason ?? null,
    restoreKey,
    orderId,
    order.order_status,
    order.payment_status
  );

  const statements = [updateOrder];

  for (const item of itemsResult.results) {
    if (item.product_id != null) {
      statements.push(
        env.DB.prepare(`
          UPDATE products
          SET stock = stock + ?,
              updated_at = datetime('now')
          WHERE id = ?
            AND EXISTS (
              SELECT 1 FROM orders
              WHERE id = ?
                AND stock_restored_at = ?
                AND order_status = 'cancelled'
            )
        `).bind(
          item.quantity,
          item.product_id,
          orderId,
          restoreKey
        )
      );
    }
  }

  const results = await env.DB.batch(statements);

  if (!results[0].meta.changes) {
    return {
      ok: false,
      status: 409,
      message: "Status pesanan berubah. Muat ulang halaman."
    };
  }

  return {
    ok: true,
    message: "Pesanan dibatalkan dan stok dikembalikan",
    originalPaymentStatus: order.payment_status
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
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

        if (
          request.headers.get("X-Setup-Key") !==
          env.CASHIER_SETUP_KEY
        ) {
          return json({
            success: false,
            message: "Kunci setup salah"
          }, 403);
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
          SELECT id, username, password_hash, is_active
          FROM cashiers
          WHERE username = ?
        `).bind(body.username).first();

        if (
          !cashier ||
          cashier.is_active !== 1 ||
          !(await verifyPassword(body.password, cashier.password_hash))
        ) {
          return json({
            success: false,
            message: "Username atau password salah"
          }, 401);
        }

        const token = randomHex(32);
        const tokenHash = await sha256(token);

        await env.DB.prepare(`
          INSERT INTO cashier_sessions
            (cashier_id, token_hash, expires_at)
          VALUES (?, ?, datetime('now', '+12 hours'))
        `).bind(cashier.id, tokenHash).run();

        return json({
          success: true,
          message: "Login berhasil",
          token,
          cashier: {
            id: cashier.id,
            username: cashier.username
          }
        });
      }
        return json({
          success: true,
          message: "Login berhasil",
          token,
          cashier: {
            id: cashier.id,
            username: cashier.username
          }
        });
      }

      // Logout kasir
      if (path === "/api/auth/logout" && method === "POST") {
        const authorization =
          request.headers.get("Authorization") || "";
        const match = authorization.match(/^Bearer\s+(.+)$/i);

        if (!match) {
          return json({
            success: false,
            message: "Token login diperlukan"
          }, 401);
        }

        await env.DB.prepare(`
          DELETE FROM cashier_sessions
          WHERE token_hash = ?
        `).bind(await sha256(match[1])).run();

        return json({
          success: true,
          message: "Logout berhasil"
        });
      }
      // Pelanggan melihat status pesanan dengan kode dan token akses.
      const customerOrderMatch = path.match(
        /^\/api\/orders\/([A-Za-z0-9-]+)$/
      );

      if (customerOrderMatch && method === "GET") {
        const result = await getCustomerOrder(
          request,
          env,
          customerOrderMatch[1]
        );

        if (result.error) return result.error;

        const itemResult = await env.DB.prepare(`
          SELECT product_name, unit_price, quantity, subtotal
          FROM order_items
          WHERE order_id = ?
          ORDER BY id
        `).bind(result.order.id).all();

        return json({
          success: true,
          data: {
            ...result.order,
            items: itemResult.results
          }
        });
      }

      // Aksi pelanggan: lapor pembayaran atau batalkan pesanan.
      const customerActionMatch = path.match(
        /^\/api\/orders\/([A-Za-z0-9-]+)\/(report-payment|cancel)$/
      );

      if (customerActionMatch && method === "POST") {
        const [, code, action] = customerActionMatch;
        const result = await getCustomerOrder(request, env, code);

        if (result.error) return result.error;

        const order = result.order;

        if (action === "report-payment") {
          const updated = await env.DB.prepare(`
            UPDATE orders
            SET order_status = 'awaiting_verification',
                payment_status = 'reported_paid',
                updated_at = datetime('now')
            WHERE id = ?
              AND order_status = 'pending_payment'
              AND payment_status = 'unpaid'
          `).bind(order.id).run();

          if (!updated.meta.changes) {
            return json({
              success: false,
              message: "Pesanan sudah diproses atau tidak dapat diubah"
            }, 409);
          }

          return json({
            success: true,
            message: "Laporan pembayaran dikirim. Menunggu verifikasi kasir.",
            order_status: "awaiting_verification",
            payment_status: "reported_paid"
          });
        }

        if (action === "cancel") {
          const cancelResult = await cancelOrderAndRestoreStock(env, {
            orderId: order.id,
            allowedStatuses: [{
              order_status: "pending_payment",
              payment_status: "unpaid"
            }]
          });

          if (!cancelResult.ok) {
            return json({
              success: false,
              message: cancelResult.message
            }, cancelResult.status);
          }

          return json({
            success: true,
            message: "Pesanan berhasil dibatalkan",
            order_status: "cancelled"
          });
        }
      }

      // Dashboard kasir: daftar pesanan
      if (path === "/api/cashier/orders" && method === "GET") {
        const auth = await requireCashier(request, env);
        if (auth.error) return auth.error;

        const result = await env.DB.prepare(`
          SELECT id, order_code, customer_name, customer_phone,
                 customer_address, customer_note, total_amount,
                 order_status, payment_status, rejection_reason,
                 created_at, updated_at
          FROM orders
          ORDER BY
            CASE order_status
              WHEN 'awaiting_verification' THEN 0
              WHEN 'pending_payment' THEN 1
              WHEN 'processing' THEN 2
              ELSE 3
            END,
            created_at DESC
          LIMIT 200
        `).all();

        return json({
          success: true,
          data: result.results
        });
      }

      // Detail item pesanan untuk kasir
      const cashierOrderItemsMatch = path.match(
        /^\/api\/cashier\/orders\/(\d+)\/items$/
      );

      if (cashierOrderItemsMatch && method === "GET") {
        const auth = await requireCashier(request, env);
        if (auth.error) return auth.error;

        const result = await env.DB.prepare(`
          SELECT product_name, unit_price, quantity, subtotal
          FROM order_items
          WHERE order_id = ?
          ORDER BY id
        `).bind(Number(cashierOrderItemsMatch[1])).all();

        return json({
          success: true,
          data: result.results
        });
      }

      // Kasir mengonfirmasi pembayaran
      const verifyOrderMatch = path.match(
        /^\/api\/cashier\/orders\/(\d+)\/verify$/
      );

      if (verifyOrderMatch && method === "PATCH") {
        const auth = await requireCashier(request, env);
        if (auth.error) return auth.error;

        const orderId = Number(verifyOrderMatch[1]);

        const updated = await env.DB.prepare(`
          UPDATE orders
          SET order_status = 'processing',
              payment_status = 'paid',
              verified_by_cashier_id = ?,
              verified_at = datetime('now'),
              updated_at = datetime('now')
          WHERE id = ?
            AND order_status = 'awaiting_verification'
            AND payment_status = 'reported_paid'
        `).bind(auth.cashier.id, orderId).run();

        if (!updated.meta.changes) {
          return json({
            success: false,
            message: "Pesanan tidak ditemukan atau sudah diproses"
          }, 409);
        }

        return json({
          success: true,
          message: "Pembayaran dikonfirmasi. Pesanan sedang dibuat.",
          order_status: "processing",
          payment_status: "paid"
        });
      }

      // Kasir menolak pesanan dan mengembalikan stok
      const rejectOrderMatch = path.match(
        /^\/api\/cashier\/orders\/(\d+)\/reject$/
      );

      if (rejectOrderMatch && method === "PATCH") {
        const auth = await requireCashier(request, env);
        if (auth.error) return auth.error;

        const body = await readJson(request);
        const reason = body?.reason;

        if (
          typeof reason !== "string" ||
          reason.trim().length < 3 ||
          reason.trim().length > 500
        ) {
          return json({
            success: false,
            message: "Alasan penolakan wajib diisi (3–500 karakter)"
          }, 400);
        }

        const orderId = Number(rejectOrderMatch[1]);

        const result = await cancelOrderAndRestoreStock(env, {
          orderId,
          allowedStatuses: [{
            order_status: "awaiting_verification",
            payment_status: "reported_paid"
          }],
          paymentStatus: "failed",
          rejectionReason: reason.trim(),
          cashierId: auth.cashier.id
        });

        if (!result.ok) {
          return json({
            success: false,
            message: result.message
          }, result.status);
        }

        return json({
          success: true,
          message: "Pesanan ditolak. Stok dikembalikan.",
          order_status: "cancelled",
          payment_status: "failed",
          rejection_reason: reason.trim()
        });
      }

      // Batalkan pesanan dari dashboard kasir
      const cashierCancelMatch = path.match(
        /^\/api\/cashier\/orders\/(\d+)\/cancel$/
      );

      if (cashierCancelMatch && method === "POST") {
        const auth = await requireCashier(request, env);
        if (auth.error) return auth.error;

        const orderId = Number(cashierCancelMatch[1]);

        const result = await cancelOrderAndRestoreStock(env, {
          orderId,
          allowedStatuses: [
            {
              order_status: "pending_payment",
              payment_status: "unpaid"
            },
            {
              order_status: "awaiting_verification",
              payment_status: "reported_paid"
            }
          ]
        });

        if (!result.ok) {
          return json({
            success: false,
            message: result.message
          }, result.status);
        }

        return json({
          success: true,
          message: result.message,
          order_status: "cancelled",
          refund_review_required: true
        });
      }

      // Kasir mengubah status pesanan menjadi sedang diantar atau selesai.
      // Database hanya menyimpan status yang diizinkan oleh CHECK constraint.
      const updateOrderStatusMatch = path.match(
        /^\/api\/cashier\/orders\/(\d+)\/status$/
      );

      if (updateOrderStatusMatch && method === "PATCH") {
        const auth = await requireCashier(request, env);
        if (auth.error) return auth.error;

        const orderId = Number(updateOrderStatusMatch[1]);
        const body = await readJson(request);
        const newStatus = body?.order_status;

        if (!["delivering", "completed"].includes(newStatus)) {
          return json({
            success: false,
            message: "Status tujuan tidak valid."
          }, 400);
        }

        try {
          let result;

          if (newStatus === "delivering") {
            // Status tampilan "Sedang Diantar"; database tetap processing.
            result = await env.DB.prepare(`
              UPDATE orders
              SET updated_at = datetime('now')
              WHERE id = ?
                AND order_status = 'processing'
                AND payment_status = 'paid'
            `).bind(orderId).run();
          } else {
            // Tandai pesanan selesai.
            result = await env.DB.prepare(`
              UPDATE orders
              SET order_status = 'completed',
                  updated_at = datetime('now')
              WHERE id = ?
                AND order_status = 'processing'
                AND payment_status = 'paid'
            `).bind(orderId).run();
          }

          if (!result.meta || result.meta.changes === 0) {
            return json({
              success: false,
              message: "Pesanan tidak ditemukan, belum dibayar, atau statusnya sudah berubah."
            }, 409);
          }

          return json({
            success: true,
            message: newStatus === "delivering"
              ? "Pesanan ditandai sedang diantar. Status database tetap processing."
              : "Pesanan berhasil diselesaikan.",
            order_status: newStatus === "delivering"
              ? "processing"
              : "completed",
            display_status: newStatus
          });
        } catch (error) {
          console.error("Gagal mengubah status pesanan:", error);

          return json({
            success: false,
            message: "Gagal memperbarui status pesanan di database."
          }, 500);
        }
      }

      // Endpoint tidak ditemukan
      return json({
        success: false,
        message: "Endpoint tidak ditemukan"
      }, 404);

    } catch (error) {
      console.error("API error:", error);

      return json({
        success: false,
        message: "Terjadi kesalahan pada server.",
        debug: error instanceof Error
          ? error.message
          : String(error)
      }, 500);
    }
  }
};
