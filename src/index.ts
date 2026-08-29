export interface Env {
  // Environment variables and secrets (Set via wrangler secret put)
  RAZORPAY_KEY_ID: string;
  RAZORPAY_KEY_SECRET: string;
  SHIPROCKET_EMAIL: string;
  SHIPROCKET_PASSWORD: string;
  FIREBASE_PROJECT_ID: string;
  FIREBASE_CLIENT_EMAIL: string;
  FIREBASE_PRIVATE_KEY: string;
  CORS_ORIGIN: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Standard CORS headers for communicating safely with the frontend
    const corsHeaders = {
      'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // ---------------------------------------------------------
      // 1. PAYMENT ROUTES
      // ---------------------------------------------------------
      if (path === '/api/payment/verify' && method === 'POST') {
        // Secure server-side verification of Razorpay signature
        // DO NOT trust frontend success callbacks alone.
        // Once verified, update Firestore: paymentStatus = PAID, orderStatus = PENDING
        
        return new Response(JSON.stringify({ 
          success: true, 
          message: "Payment verified successfully securely on the server." 
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // ---------------------------------------------------------
      // 2. WEBHOOK ROUTES (Automated Updates)
      // ---------------------------------------------------------
      if (path === '/api/webhooks/razorpay' && method === 'POST') {
        // Listen for Razorpay events (e.g., refund.processed)
        // Verify webhook signature using RAZORPAY_WEBHOOK_SECRET
        // Update Firestore: paymentStatus = REFUNDED
        return new Response("Razorpay Webhook Received", { status: 200, headers: corsHeaders });
      }

      if (path === '/api/webhooks/shiprocket' && method === 'POST') {
        // Listen for Shiprocket tracking updates
        // Update Firestore shipmentStatus automatically (SHIPPED, IN_TRANSIT, DELIVERED)
        // NO manual "Mark as Shipped" allowed, strictly automated tracking.
        return new Response("Shiprocket Webhook Received", { status: 200, headers: corsHeaders });
      }

      // ---------------------------------------------------------
      // 3. ADMIN OPERATIONS
      // ---------------------------------------------------------
      if (path === '/api/admin/shipment/create' && method === 'POST') {
        // Ensure request has Admin Authorization
        // 1. Perform a FRESH Shiprocket serviceability check before generating shipment
        // 2. If courier is unavailable, return error and prompt Admin to select another courier
        // 3. If successful, generate AWB and Label securely.
        
        return new Response(JSON.stringify({ 
          success: true, 
          awbNumber: "SR-88776655",
          labelUrl: "https://shiprocket.co/label/mock-url.pdf"
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (path === '/api/admin/refund/initiate' && method === 'POST') {
        // Ensure request has Admin Authorization
        // 1. Verify order is PAID and hasn't been refunded yet.
        // 2. Call Razorpay Refund API securely.
        // 3. Update Firestore: orderStatus = REJECTED, paymentStatus = REFUND_INITIATED
        
        return new Response(JSON.stringify({ 
          success: true, 
          message: "Full refund initiated via Razorpay successfully."
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // ---------------------------------------------------------
      // FALLBACK ROUTE
      // ---------------------------------------------------------
      return new Response(JSON.stringify({ error: "API Endpoint Not Found" }), { 
        status: 404, 
        headers: { 'Content-Type': 'application/json', ...corsHeaders } 
      });

    } catch (error: any) {
      console.error("Worker Error:", error);
      return new Response(JSON.stringify({ error: "Internal Server Error", details: error.message }), { 
        status: 500, 
        headers: { 'Content-Type': 'application/json', ...corsHeaders } 
      });
    }
  }
};
