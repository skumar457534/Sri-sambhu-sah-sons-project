export interface Env {
  // Firebase Secrets
  FIREBASE_CLIENT_EMAIL: string;
  FIREBASE_PRIVATE_KEY: string;
  FIREBASE_PROJECT_ID: string;

  // Razorpay Secrets
  RAZORPAY_KEY_ID: string;
  RAZORPAY_KEY_SECRET: string;

  // Shiprocket Secrets
  SHIPROCKET_EMAIL: string;
  SHIPROCKET_PASSWORD: string;

  CORS_ORIGIN: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // -----------------------------------------------------
    // CORS HEADERS (वेबसाइट को सर्वर से बात करने की आज़ादी)
    // -----------------------------------------------------
    const corsHeaders = {
      'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // =========================================================
      // 0. RAZORPAY: CREATE ORDER API (NEW)
      // =========================================================
      if (path === '/api/payment/create-order' && method === 'POST') {
        const { amount } = await request.json() as any;
        if (!amount) return new Response(JSON.stringify({ error: "Amount required" }), { status: 400, headers: corsHeaders });

        const authHeader = "Basic " + btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
        const rzpResponse = await fetch("https://api.razorpay.com/v1/orders", {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
          body: JSON.stringify({ amount: Math.round(amount * 100), currency: "INR", receipt: "receipt_" + Date.now() })
        });
        
        const rzpData = await rzpResponse.json();
        return new Response(JSON.stringify(rzpData), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
      }

      // =========================================================
      // 1. RAZORPAY: PAYMENT VERIFICATION API
      // =========================================================
      if (path === '/api/payment/verify' && method === 'POST') {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = await request.json() as any;

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
          return new Response(JSON.stringify({ success: false, error: "Missing parameters" }), { status: 400, headers: corsHeaders });
        }

        // Crypto validation (HMAC SHA256)
        const encoder = new TextEncoder();
        const data = encoder.encode(razorpay_order_id + "|" + razorpay_payment_id);
        const key = await crypto.subtle.importKey(
          "raw", encoder.encode(env.RAZORPAY_KEY_SECRET),
          { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        );
        
        const signatureBuffer = await crypto.subtle.sign("HMAC", key, data);
        const signatureArray = Array.from(new Uint8Array(signatureBuffer));
        const generatedSignature = signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');

        if (generatedSignature === razorpay_signature) {
          return new Response(JSON.stringify({ success: true, message: "Payment Verified" }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } else {
          return new Response(JSON.stringify({ success: false, error: "Invalid signature" }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
      }

      // =========================================================
      // 2. RAZORPAY: AUTO REFUND API
      // =========================================================
      if (path === '/api/admin/refund' && method === 'POST') {
        const { payment_id, amount } = await request.json() as any;
        if (!payment_id) return new Response(JSON.stringify({ success: false, error: "Payment ID required" }), { status: 400, headers: corsHeaders });

        const authHeader = "Basic " + btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
        const refundPayload: any = {};
        if (amount) refundPayload.amount = Math.round(amount * 100); // Amount in paise

        const rzpResponse = await fetch(`https://api.razorpay.com/v1/payments/${payment_id}/refund`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
          body: JSON.stringify(refundPayload)
        });

        const rzpData = await rzpResponse.json() as any;
        if (rzpResponse.ok) {
          return new Response(JSON.stringify({ success: true, refund_id: rzpData.id }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } else {
          return new Response(JSON.stringify({ success: false, error: rzpData.error?.description }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
      }

      // =========================================================
      // HELPER: GET SHIPROCKET TOKEN
      // =========================================================
      const getShiprocketToken = async () => {
        const authRes = await fetch("https://apiv2.shiprocket.in/v1/external/auth/login", {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: env.SHIPROCKET_EMAIL, password: env.SHIPROCKET_PASSWORD })
        });
        if (!authRes.ok) throw new Error("Shiprocket Authentication Failed");
        const authData = await authRes.json() as any;
        return authData.token;
      };

      // =========================================================
      // 3. SHIPROCKET: CHECK COURIER SERVICEABILITY
      // =========================================================
      if (path === '/api/shiprocket/serviceability' && method === 'POST') {
        const { delivery_postcode, weight, cod } = await request.json() as any;
        
        // Use your pickup pincode here (Deoghar: 814112)
        const pickup_postcode = "814112"; 
        const token = await getShiprocketToken();

        const courierRes = await fetch(`https://apiv2.shiprocket.in/v1/external/courier/serviceability/?pickup_postcode=${pickup_postcode}&delivery_postcode=${delivery_postcode}&weight=${weight}&cod=${cod || 0}`, {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${token}` }
        });

        const courierData = await courierRes.json() as any;
        if (courierData.status === 200) {
          return new Response(JSON.stringify({ success: true, data: courierData.data }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } else {
          return new Response(JSON.stringify({ success: false, error: "Service not available for this PIN code" }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
      }

      // =========================================================
      // 4. SHIPROCKET: CREATE ORDER & AWB
      // =========================================================
      if (path === '/api/shiprocket/create-order' && method === 'POST') {
        const orderDetails = await request.json() as any;
        const token = await getShiprocketToken();

        const createRes = await fetch("https://apiv2.shiprocket.in/v1/external/orders/create/adhoc", {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
          body: JSON.stringify(orderDetails)
        });

        const createData = await createRes.json() as any;
        if (createRes.ok && createData.order_id) {
          return new Response(JSON.stringify({ success: true, shiprocket_order_id: createData.order_id, shipment_id: createData.shipment_id }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } else {
          return new Response(JSON.stringify({ success: false, error: "Failed to generate Shiprocket Order", details: createData }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
      }

      // =========================================================
      // 5. SHIPROCKET: LIVE TRACKING BY AWB (NEW)
      // =========================================================
      if (path === '/api/shiprocket/track' && method === 'GET') {
        const awb = url.searchParams.get('awb');
        if (!awb) return new Response(JSON.stringify({ success: false, error: "AWB required" }), { status: 400, headers: corsHeaders });
        
        try {
            const token = await getShiprocketToken();
            const trackRes = await fetch(`https://apiv2.shiprocket.in/v1/external/courier/track/awb/${awb}`, {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${token}` }
            });

            const trackData = await trackRes.json() as any;
            return new Response(JSON.stringify({ success: true, data: trackData }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (error: any) {
            return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
      }

      // =========================================================
      // 6. SHIPROCKET: GENERATE LABEL (PDF)
      // =========================================================
      if (path === '/api/shiprocket/label' && method === 'POST') {
        const { shipment_id } = await request.json() as any;
        const token = await getShiprocketToken();

        const labelRes = await fetch("https://apiv2.shiprocket.in/v1/external/courier/generate/label", {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
          body: JSON.stringify({ shipment_id: [shipment_id] }) // Shiprocket expects an array of shipment IDs
        });

        const labelData = await labelRes.json() as any;
        if (labelRes.ok && labelData.label_created === 1) {
          return new Response(JSON.stringify({ success: true, label_url: labelData.label_url }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } else {
          return new Response(JSON.stringify({ success: false, error: "Label not ready yet or failed", details: labelData }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
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
      return new Response(JSON.stringify({ success: false, error: "Internal Server Error", details: error.message }), { 
        status: 500, 
        headers: { 'Content-Type': 'application/json', ...corsHeaders } 
      });
    }
  }
};


