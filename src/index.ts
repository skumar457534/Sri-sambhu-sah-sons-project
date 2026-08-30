export interface Env {
  // Environment variables and secrets
  RAZORPAY_KEY_ID: string;
  RAZORPAY_KEY_SECRET: string;
  CORS_ORIGIN: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS Headers for secure communication with your HTML frontend
    const corsHeaders = {
      'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    };

    // Handle preflight requests
    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // =========================================================
      // 1. PAYMENT VERIFICATION API
      // =========================================================
      if (path === '/api/payment/verify' && method === 'POST') {
        const body = await request.json() as any;
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = body;

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
          return new Response(JSON.stringify({ success: false, error: "Missing parameters" }), { status: 400, headers: corsHeaders });
        }

        // Crypto validation (HMAC SHA256)
        const encoder = new TextEncoder();
        const data = encoder.encode(razorpay_order_id + "|" + razorpay_payment_id);
        const key = await crypto.subtle.importKey(
          "raw", 
          encoder.encode(env.RAZORPAY_KEY_SECRET),
          { name: "HMAC", hash: "SHA-256" }, 
          false, 
          ["sign"]
        );
        
        const signatureBuffer = await crypto.subtle.sign("HMAC", key, data);
        const signatureArray = Array.from(new Uint8Array(signatureBuffer));
        const generatedSignature = signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');

        if (generatedSignature === razorpay_signature) {
          // Signature matches! Payment is authentic.
          return new Response(JSON.stringify({ 
            success: true, 
            message: "Payment verified successfully securely on the server." 
          }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } else {
          // Fake or tampered payment
          return new Response(JSON.stringify({ 
            success: false, 
            error: "Invalid signature. Payment verification failed." 
          }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
      }

      // =========================================================
      // 2. AUTO REFUND API (Admin Only)
      // =========================================================
      if (path === '/api/admin/refund/initiate' && method === 'POST') {
        const body = await request.json() as any;
        const { payment_id, amount, admin_token } = body;

        if (!payment_id) {
          return new Response(JSON.stringify({ success: false, error: "Payment ID required" }), { status: 400, headers: corsHeaders });
        }

        // NOTE: In production, verify the `admin_token` with Firebase Auth REST API here 
        // to ensure the person making this request is actually the Admin.

        // Call Razorpay Refund API
        const authHeader = "Basic " + btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
        
        // Amount is sent in paise to Razorpay
        const refundPayload: any = {};
        if (amount) refundPayload.amount = Math.round(amount * 100); 

        const rzpResponse = await fetch(`https://api.razorpay.com/v1/payments/${payment_id}/refund`, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json', 
            'Authorization': authHeader 
          },
          body: JSON.stringify(refundPayload)
        });

        const rzpData = await rzpResponse.json() as any;

        if (rzpResponse.ok) {
          return new Response(JSON.stringify({ 
            success: true, 
            message: "Refund initiated successfully via Razorpay.",
            refund_id: rzpData.id
          }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } else {
          return new Response(JSON.stringify({ 
            success: false, 
            error: rzpData.error?.description || "Razorpay refund failed." 
          }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
      }

      // =========================================================
      // FALLBACK ROUTE
      // =========================================================
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
