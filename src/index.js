const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json; charset=utf-8"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    if (request.method !== "GET") {
      return json({
        success: false,
        message: "Method tidak diizinkan"
      }, 405);
    }

    // Tes koneksi backend dan database
    if (path === "/api/health") {
      try {
        await env.DB.prepare("SELECT 1").first();

        return json({
          success: true,
          message: "Cake Order API aktif",
          database: "connected"
        });
      } catch {
        return json({
          success: false,
          message: "Koneksi database gagal"
        }, 500);
      }
    }

    // Daftar semua produk aktif
    if (path === "/api/products") {
      try {
        const result = await env.DB.prepare(`
          SELECT
            id,
            name,
            description,
            price,
            image_url,
            category,
            stock
          FROM products
          WHERE is_active = 1
          ORDER BY id DESC
        `).all();

        return json({
          success: true,
          data: result.results
        });
      } catch {
        return json({
          success: false,
          message: "Gagal mengambil produk. Periksa struktur tabel products."
        }, 500);
      }
    }

    // Detail satu produk berdasarkan ID
    const match = path.match(/^\/api\/products\/(\d+)$/);

    if (match) {
      try {
        const product = await env.DB.prepare(`
          SELECT
            id,
            name,
            description,
            price,
            image_url,
            category,
            stock
          FROM products
          WHERE id = ? AND is_active = 1
        `).bind(Number(match[1])).first();

        if (!product) {
          return json({
            success: false,
            message: "Produk tidak ditemukan"
          }, 404);
        }

        return json({
          success: true,
          data: product
        });
      } catch {
        return json({
          success: false,
          message: "Gagal mengambil detail produk"
        }, 500);
      }
    }

    return json({
      success: false,
      message: "Endpoint tidak ditemukan"
    }, 404);
  }
};
