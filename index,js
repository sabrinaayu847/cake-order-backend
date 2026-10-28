export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      try {
        const result = await env.DB
          .prepare("SELECT 1 AS connected")
          .first();

        return Response.json({
          success: true,
          message: "Cake Order API aktif",
          database: result?.connected === 1
            ? "connected"
            : "disconnected"
        });
      } catch (error) {
        return Response.json({
          success: false,
          message: "Koneksi database gagal"
        }, { status: 500 });
      }
    }

    return Response.json({
      success: true,
      message: "Cake Order Backend"
    });
  }
};
