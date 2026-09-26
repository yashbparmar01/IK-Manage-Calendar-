// ============================================================
// Supabase Edge Function: auth-otp
// Description: Secure OTP generation, Resend dispatch & verification
// Environment Variables Required in Supabase:
//   - RESEND_API_KEY (Already configured in Supabase secrets)
//   - RESEND_FROM_EMAIL (Optional: defaults to "InfiniKraft <onboarding@resend.dev>")
//   - SUPABASE_URL (Provided automatically by Supabase)
//   - SUPABASE_SERVICE_ROLE_KEY (Provided automatically by Supabase)
// ============================================================

import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

async function hashOtp(otp: string, salt: string): Promise<string> {
  const enc = new TextEncoder();
  const data = enc.encode(`${salt}:${otp}`);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function generate6DigitOtp(): string {
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  // Guarantee a 6-digit number between 100000 and 999999
  const num = 100000 + (array[0] % 900000);
  return num.toString();
}

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", {
      status: 200,
      headers: corsHeaders,
    });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
    const resendApiKey = Deno.env.get("RESEND_API_KEY") || "";
    const resendFromEmail = Deno.env.get("RESEND_FROM_EMAIL") || "InfiniKraft <onboarding@resend.dev>";

    if (!supabaseUrl || !supabaseServiceKey) {
      return new Response(JSON.stringify({ error: "Server misconfiguration: Supabase credentials missing" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 1. Authenticate user via JWT Bearer token
    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "Missing or invalid authorization header" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const token = authHeader.replace("Bearer ", "").trim();
    const adminClient = createClient(supabaseUrl, supabaseServiceKey, {
      auth: { persistSession: false },
    });

    const { data: { user }, error: userError } = await adminClient.auth.getUser(token);
    if (userError || !user || !user.email) {
      return new Response(JSON.stringify({ error: "Unauthorized session or expired token" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const email = user.email.toLowerCase().trim();

    // 2. Strict Server-Side Gmail enforcement
    if (!email.endsWith("@gmail.com")) {
      return new Response(JSON.stringify({ error: "Restricted domain: Only @gmail.com accounts are permitted" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body = await req.json().catch(() => ({}));
    const action = body.action;

    // -------------------------------------------------------------------------
    // ACTION: SEND OTP
    // -------------------------------------------------------------------------
    if (action === "send") {
      if (!resendApiKey) {
        return new Response(JSON.stringify({ error: "Email service misconfiguration: RESEND_API_KEY secret not found" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Rate limit check: only allow 1 request per 60 seconds per user
      const oneMinuteAgo = new Date(Date.now() - 60 * 1000).toISOString();
      const { data: recentOtps } = await adminClient
        .from("email_otps")
        .select("id, created_at")
        .eq("user_id", user.id)
        .gte("created_at", oneMinuteAgo);

      if (recentOtps && recentOtps.length > 0) {
        return new Response(JSON.stringify({
          error: "rate_limited",
          message: "Please wait 60 seconds before requesting a new verification code.",
        }), {
          status: 429,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Invalidate existing unused codes for this user
      await adminClient
        .from("email_otps")
        .update({ verified: false, expires_at: new Date().toISOString() })
        .eq("user_id", user.id)
        .eq("verified", false);

      // Generate 6-digit secure OTP and hash it with user.id salt
      const otp = generate6DigitOtp();
      const otpHash = await hashOtp(otp, user.id);
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 minutes

      // Store hashed OTP
      const { error: insertError } = await adminClient.from("email_otps").insert({
        user_id: user.id,
        email: email,
        otp_hash: otpHash,
        expires_at: expiresAt,
        attempts: 0,
        max_attempts: 5,
        verified: false,
      });

      if (insertError) {
        return new Response(JSON.stringify({ error: "Failed to initialize verification code" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Dispatch OTP email via Resend API
      const emailHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f7f9fa; margin: 0; padding: 30px; color: #1e293b; }
    .card { max-width: 480px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; padding: 36px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
    .brand { font-size: 22px; font-weight: 800; color: #0f172a; margin-bottom: 20px; letter-spacing: -0.02em; }
    .brand span { color: #f43f5e; }
    .code-box { background: #f1f5f9; border-radius: 8px; padding: 18px; text-align: center; margin: 24px 0; letter-spacing: 6px; font-size: 32px; font-weight: 700; color: #0f172a; font-family: monospace; }
    .footer { font-size: 12px; color: #64748b; margin-top: 30px; line-height: 1.6; border-top: 1px solid #e2e8f0; padding-top: 18px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">InfiniKraft<span>.</span></div>
    <p>Hello,</p>
    <p>Your InfiniKraft Brand Calendar verification code is:</p>
    <div class="code-box">${otp}</div>
    <p>This code is valid for <strong>5 minutes</strong>.</p>
    <p>If you did not request this code, you can safely ignore this email.</p>
    <div class="footer">
      Regards,<br/>
      <strong>InfiniKraft</strong>
    </div>
  </div>
</body>
</html>
      `.trim();

      const emailText = `Hello,\n\nYour InfiniKraft Brand Calendar verification code is:\n\n${otp}\n\nThis code is valid for 5 minutes.\n\nIf you did not request this code, you can safely ignore this email.\n\nRegards,\nInfiniKraft`;

      const resendRes = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${resendApiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: resendFromEmail,
          to: [email],
          subject: "Your InfiniKraft Verification Code",
          html: emailHtml,
          text: emailText,
        }),
      });

      if (!resendRes.ok) {
        const resendError = await resendRes.text().catch(() => "Unknown Resend error");
        console.error("Resend API dispatch failure:", resendError);
        return new Response(JSON.stringify({
          error: "email_dispatch_failed",
          message: "Unable to send verification email. Please check domain/sender settings.",
        }), {
          status: 502,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      return new Response(JSON.stringify({
        ok: true,
        message: "Verification code sent to your email",
        expires_at: expiresAt,
      }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // -------------------------------------------------------------------------
    // ACTION: VERIFY OTP
    // -------------------------------------------------------------------------
    if (action === "verify") {
      const inputOtp = String(body.otp || "").trim();
      if (!inputOtp || inputOtp.length !== 6 || !/^\d{6}$/.test(inputOtp)) {
        return new Response(JSON.stringify({ error: "invalid_format", message: "Please enter a valid 6-digit code." }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Fetch the latest active unverified OTP for this user
      const { data: otps, error: fetchErr } = await adminClient
        .from("email_otps")
        .select("*")
        .eq("user_id", user.id)
        .eq("verified", false)
        .order("created_at", { ascending: false })
        .limit(1);

      if (fetchErr || !otps || otps.length === 0) {
        return new Response(JSON.stringify({
          error: "no_active_otp",
          message: "No active verification code found. Please request a new code.",
        }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const activeOtp = otps[0];

      // Check expiration
      if (new Date(activeOtp.expires_at).getTime() < Date.now()) {
        return new Response(JSON.stringify({
          error: "otp_expired",
          message: "This code has expired. Please click 'Resend Code'.",
        }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Check max attempts
      if (activeOtp.attempts >= activeOtp.max_attempts) {
        return new Response(JSON.stringify({
          error: "too_many_attempts",
          message: "Too many incorrect attempts. For security, please request a fresh code.",
        }), {
          status: 429,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Compare hashes
      const inputHash = await hashOtp(inputOtp, user.id);
      if (inputHash !== activeOtp.otp_hash) {
        const nextAttempts = activeOtp.attempts + 1;
        await adminClient
          .from("email_otps")
          .update({ attempts: nextAttempts })
          .eq("id", activeOtp.id);

        const attemptsLeft = activeOtp.max_attempts - nextAttempts;
        return new Response(JSON.stringify({
          error: "invalid_otp",
          message: attemptsLeft > 0
            ? `Incorrect code. ${attemptsLeft} attempt${attemptsLeft === 1 ? "" : "s"} remaining.`
            : "Too many incorrect attempts. Please request a new code.",
          attempts_left: attemptsLeft,
        }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Mark OTP as verified
      await adminClient
        .from("email_otps")
        .update({
          verified: true,
          verified_at: new Date().toISOString(),
        })
        .eq("id", activeOtp.id);

      // Mark profile as otp_verified
      await adminClient
        .from("profiles")
        .update({ otp_verified: true })
        .eq("id", user.id);

      return new Response(JSON.stringify({
        ok: true,
        verified: true,
        message: "Email successfully verified",
      }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Invalid action. Supported actions: 'send', 'verify'" }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err: any) {
    console.error("Unhandled error in auth-otp function:", err);
    return new Response(JSON.stringify({ error: "internal_error", message: "An unexpected error occurred." }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
