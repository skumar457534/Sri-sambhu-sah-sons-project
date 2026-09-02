export interface Env {
  FIREBASE_PROJECT_ID: string;
  FIREBASE_API_KEY: string;
  FIREBASE_ADMIN_EMAIL: string;
  FIREBASE_ADMIN_PASSWORD: string;

  RAZORPAY_KEY_ID: string;
  RAZORPAY_KEY_SECRET: string;
  RAZORPAY_WEBHOOK_SECRET: string;

  SHIPROCKET_EMAIL: string;
  SHIPROCKET_PASSWORD: string;
  SHIPROCKET_WEBHOOK_TOKEN: string;

  BREVO_API_KEY: string;
  CORS_ORIGIN: string;
}

// =========================================================
// SMART CACHE SYSTEM: To Prevent 2-Hour Account Locks
// =========================================================
let cachedShiprocketToken: string | null = null;
let tokenExpiryTime: number = 0;
let cachedFirebaseToken: string | null = null; // Cache for Firebase Admin Token

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // -----------------------------------------------------
    // CORS HEADERS
    // -----------------------------------------------------
    const corsHeaders = {
      'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, x-razorpay-signature, x-api-key',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // =========================================================
      // HELPER: GET FIREBASE AUTH TOKEN (FOR WORKER TO WRITE TO DB)
      // =========================================================
      const getFirebaseToken = async () => {
        if (cachedFirebaseToken) return cachedFirebaseToken;
        const res = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${env.FIREBASE_API_KEY}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: env.FIREBASE_ADMIN_EMAIL, password: env.FIREBASE_ADMIN_PASSWORD, returnSecureToken: true })
        });
        const data = await res.json() as any;
        if (data.idToken) {
           cachedFirebaseToken = data.idToken;
           return data.idToken;
        }
        throw new Error("Firebase Auth Failed in Worker");
      };

      // =========================================================
      // HELPER: UPDATE FIRESTORE DOCUMENT VIA REST API
      // =========================================================
      const updateFirestoreOrder = async (documentId: string, fields: any) => {
        const token = await getFirebaseToken();
        const projectId = env.FIREBASE_PROJECT_ID; 
        
        // Convert JSON to Firestore REST format
        const firestoreFields: any = {};
        for (const [key, value] of Object.entries(fields)) {
            if (typeof value === 'string') firestoreFields[key] = { stringValue: value };
            else if (typeof value === 'number') firestoreFields[key] = { integerValue: value };
            else if (typeof value === 'boolean') firestoreFields[key] = { booleanValue: value };
        }

        let updateMask = Object.keys(fields).map(k => `updateMask.fieldPaths=${k}`).join('&');
        
        await fetch(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/orders/${documentId}?${updateMask}`, {
            method: 'PATCH',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ fields: firestoreFields })
        });
      };

      // =========================================================
      // 0. RAZORPAY: CREATE ORDER API
      // =========================================================
      if (path === '/api/payment/create-order' && method === 'POST') {
        const { amount, receipt } = await request.json() as any;
        if (!amount) return new Response(JSON.stringify({ error: "Amount required" }), { status: 400, headers: corsHeaders });

        const authHeader = "Basic " + btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
        const rzpResponse = await fetch("https://api.razorpay.com/v1/orders", {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
          body: JSON.stringify({ 
              amount: Math.round(amount * 100), 
              currency: "INR", 
              receipt: receipt || ("receipt_" + Date.now()) 
          })
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
      // NEW: RAZORPAY WEBHOOK (The Safety Net)
      // =========================================================
      if (path === '/api/razorpay/webhook' && method === 'POST') {
        const signature = request.headers.get('x-razorpay-signature');
        const bodyText = await request.text();

        // Verify Webhook Signature
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey("raw", encoder.encode(env.RAZORPAY_WEBHOOK_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const signatureBuffer = await crypto.subtle.sign("HMAC", key, encoder.encode(bodyText));
        const expectedSignature = Array.from(new Uint8Array(signatureBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

        if (signature !== expectedSignature) {
            return new Response("Invalid Signature", { status: 400 });
        }

        const payload = JSON.parse(bodyText);
        
        // Handle Payment Captured
        if (payload.event === 'payment.captured') {
            const paymentEntity = payload.payload.payment.entity;
            const firebaseOrderId = paymentEntity.notes?.firebase_order_id;
            
            if (firebaseOrderId) {
                // Update Firestore Order via REST API
                await updateFirestoreOrder(firebaseOrderId, {
                    status: 'PENDING',
                    paymentStatus: 'PAID',
                    razorpayPaymentId: paymentEntity.id
                });
            }
        }
        return new Response("Webhook Processed", { status: 200, headers: corsHeaders });
      }

      // =========================================================
      // 2. RAZORPAY: AUTO REFUND API
      // =========================================================
      if (path === '/api/admin/refund' && method === 'POST') {
        const { payment_id, amount } = await request.json() as any;
        if (!payment_id) return new Response(JSON.stringify({ success: false, error: "Payment ID required" }), { status: 400, headers: corsHeaders });

        const authHeader = "Basic " + btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
        const refundPayload: any = {};
        if (amount) refundPayload.amount = Math.round(amount * 100);

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
      // HELPER: GET SHIPROCKET TOKEN (WITH CACHING)
      // =========================================================
      const getShiprocketToken = async () => {
        const currentTime = Date.now();
        if (cachedShiprocketToken && currentTime < tokenExpiryTime) {
          return cachedShiprocketToken;
        }

        const authRes = await fetch("https://apiv2.shiprocket.in/v1/external/auth/login", {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: env.SHIPROCKET_EMAIL, password: env.SHIPROCKET_PASSWORD })
        });
        
        if (!authRes.ok) {
          const errText = await authRes.text();
          throw new Error(`Shiprocket Authentication Failed: ${errText}`);
        }
        
        const authData = await authRes.json() as any;
        cachedShiprocketToken = authData.token;
        tokenExpiryTime = currentTime + (9 * 24 * 60 * 60 * 1000);

        return cachedShiprocketToken;
      };

      // =========================================================
      // 3. SHIPROCKET: CHECK COURIER SERVICEABILITY
      // =========================================================
      if (path === '/api/shiprocket/serviceability' && method === 'POST') {
        const { delivery_postcode, weight, cod } = await request.json() as any;
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
          return new Response(JSON.stringify({ success: false, error: courierData.message || "Service not available for this PIN code" }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
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
      // 5. SHIPROCKET: LIVE TRACKING BY AWB
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
          body: JSON.stringify({ shipment_id: [shipment_id] })
        });

        const labelData = await labelRes.json() as any;
        if (labelRes.ok && labelData.label_created === 1) {
          return new Response(JSON.stringify({ success: true, label_url: labelData.label_url }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } else {
          return new Response(JSON.stringify({ success: false, error: "Label not ready yet or failed", details: labelData }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
      }

      // =========================================================
      // 7. SHIPROCKET WEBHOOK (AUTOMATIC TRACKING UPDATE)
      // =========================================================
      // Notice: The path matches exactly what Shiprocket allowed
      if (path === '/api/webhook/tracking') {
        
        // Shiprocket pings with GET first to verify the URL
        if (method === 'GET' || method === 'OPTIONS') {
            return new Response("Webhook is Live and Verified!", { status: 200, headers: corsHeaders });
        }

        // When Shiprocket actually sends tracking data
        if (method === 'POST') {
            const receivedToken = request.headers.get('x-api-key');

            if (env.SHIPROCKET_WEBHOOK_TOKEN && receivedToken !== env.SHIPROCKET_WEBHOOK_TOKEN) {
               return new Response(JSON.stringify({ success: false, error: 'Invalid webhook token' }), { status: 401, headers: corsHeaders });
            }

            const payload = await request.json().catch(() => null) as any;
            
            // If it's a test or empty payload
            if (!payload || !payload.awb) {
               return new Response("Webhook Received (No AWB)", { status: 200, headers: corsHeaders });
            }

            // Map Shiprocket Status to Firebase Status
            const currentStatus = String(payload.current_status).toUpperCase();
            let firebaseStatus = '';

            if (currentStatus === 'DELIVERED') firebaseStatus = 'DELIVERED';
            else if (currentStatus === 'OUT FOR DELIVERY') firebaseStatus = 'OUT_FOR_DELIVERY';
            else if (currentStatus === 'IN TRANSIT') firebaseStatus = 'IN_TRANSIT';
            else if (currentStatus === 'SHIPPED' || currentStatus === 'PICKED UP') firebaseStatus = 'SHIPPED';

            if (firebaseStatus !== '') {
               // Full automation requires document ID lookup which is complex via REST.
               // We acknowledge the hook for now. In future you can add logic here to auto-update Firestore.
               console.log(`Shiprocket Webhook: AWB ${payload.awb} is now ${firebaseStatus}`);
            }

            return new Response("Webhook Processed", { status: 200, headers: corsHeaders });
        }
      }

      // =========================================================
      // 8. SEND EMAIL VIA BREVO (ACCEPT / REJECT)
      // =========================================================
      if (path === '/api/email/send' && method === 'POST') {
        const { type, email, name, orderId, awb, amount } = await request.json() as any;

        if (!env.BREVO_API_KEY) {
           return new Response(JSON.stringify({ success: false, error: "Brevo API key not set" }), { status: 500, headers: corsHeaders });
        }

        let subject = "";
        let htmlContent = "";

        if (type === 'ACCEPT') {
           subject = "Your Order is Accepted & Processing! 🚀";
           htmlContent = `
              <div style="font-family: Arial, sans-serif; max-w: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
                  <div style="text-align: center; border-bottom: 2px solid #f3f4f6; padding-bottom: 15px; margin-bottom: 20px;">
                      <h1 style="color: #7B1818; margin: 0;">Sri Shambhu Sha & Sons</h1>
                      <p style="color: #D4AF37; margin: 0; font-size: 12px; letter-spacing: 2px;">DEOGHAR</p>
                  </div>
                  <h2 style="color: #333;">Hi ${name},</h2>
                  <p style="color: #555; line-height: 1.5;">Thank you for your order! Your authentic Baba Dham Peda order has been <strong>successfully accepted</strong> and is currently being packed with care.</p>
                  <div style="background-color: #fcfcfc; padding: 15px; border-radius: 8px; margin: 20px 0; border: 1px solid #eee;">
                      <p style="margin: 0 0 10px 0; color: #555;"><strong>Order ID:</strong> ${orderId}</p>
                      <p style="margin: 0; color: #555;"><strong>Tracking AWB:</strong> <span style="color: #D4AF37; font-weight: bold; font-size: 16px;">${awb}</span></p>
                  </div>
                  <p style="color: #555;">As soon as our courier partner picks up and scans your package, you will automatically receive an SMS/Email with live tracking updates.</p>
                  <div style="text-align: center; margin: 30px 0;">
                      <a href="https://srishambhushaandsons.in/track_order.html" style="background-color: #7B1818; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Track My Order</a>
                  </div>
                  <p style="font-size: 12px; color: #999; text-align: center; border-top: 1px solid #eee; padding-top: 20px;">For any support, reply to this email or contact us via WhatsApp.</p>
              </div>
           `;
        } else if (type === 'REJECT') {
           subject = "Order Cancelled & Refund Initiated";
           htmlContent = `
              <div style="font-family: Arial, sans-serif; max-w: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
                  <div style="text-align: center; border-bottom: 2px solid #f3f4f6; padding-bottom: 15px; margin-bottom: 20px;">
                      <h1 style="color: #7B1818; margin: 0;">Sri Shambhu Sha & Sons</h1>
                      <p style="color: #D4AF37; margin: 0; font-size: 12px; letter-spacing: 2px;">DEOGHAR</p>
                  </div>
                  <h2 style="color: #333;">Hi ${name},</h2>
                  <p style="color: #555; line-height: 1.5;">We are sorry to inform you that we are currently unable to fulfill your Order <strong>${orderId}</strong>.</p>
                  <div style="background-color: #fff3f3; padding: 15px; border-radius: 8px; margin: 20px 0; border: 1px solid #ffcdd2;">
                      <p style="margin: 0 0 10px 0; color: #d32f2f;"><strong>Status:</strong> Cancelled</p>
                      <p style="margin: 0; color: #d32f2f;"><strong>Refund:</strong> ₹${amount} has been successfully initiated.</p>
                  </div>
                  <p style="color: #555;">Your refund has been initiated to your original payment method via Razorpay and should reflect in your bank account within 3-5 business days.</p>
                  <p style="font-size: 12px; color: #999; text-align: center; border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px;">For any support, reply to this email or contact us via WhatsApp.</p>
              </div>
           `;
        }

        const emailPayload = {
            sender: { name: "Sri Shambhu Sha & Sons", email: "srishambhushaandsons@gmail.com" }, 
            to: [{ email: email, name: name }],
            subject: subject,
            htmlContent: htmlContent
        };

        const brevoRes = await fetch("https://api.brevo.com/v3/smtp/email", {
            method: "POST",
            headers: {
                "accept": "application/json",
                "api-key": env.BREVO_API_KEY,
                "content-type": "application/json"
            },
            body: JSON.stringify(emailPayload)
        });

        const brevoData = await brevoRes.json();
        return new Response(JSON.stringify({ success: brevoRes.ok, data: brevoData }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
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
