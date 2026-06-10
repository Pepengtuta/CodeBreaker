<?php
// ============================================
// mailer.php — OTP Email Helper
//
// Included by forgot_password.php and
// otp_verify.php. Uses PHP's native mail()
// function — works with XAMPP sendmail
// configured in php.ini.
// ============================================

function send_otp_email($to, $otp, $subject = 'Code Breaker — Your Password Reset OTP') {
    $from = 'no-reply@codebreaker.local';

    $headers  = "From: $from\r\n";
    $headers .= "Reply-To: $from\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-type: text/html; charset=UTF-8\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion() . "\r\n";

    $body = "
    <html>
    <body style='font-family: sans-serif; background: #ffffff; color: #333333; padding: 40px;'>
        <div style='max-width: 480px; margin: 0 auto; background: #f8f9fa;
                    border: 1px solid #dee2e6; border-radius: 8px; padding: 32px;'>
            <h2 style='color: #0066cc; margin-bottom: 8px;'>[ CODE BREAKER ]</h2>
            <p style='color: #6c757d; margin-bottom: 24px;'>Password Reset Request</p>
            <p style='margin-bottom: 16px;'>
                Use the OTP below to continue your password reset.
                It expires in <strong>5 minutes</strong>.
            </p>
            <div style='background: #ffffff; border: 1px solid #dee2e6; border-radius: 8px;
                        padding: 20px; text-align: center; margin: 24px 0;'>
                <span style='font-family: monospace; font-size: 2rem; font-weight: bold;
                             letter-spacing: 8px; color: #0066cc;'>
                    $otp
                </span>
            </div>
            <p style='color: #6c757d; font-size: 0.85rem;'>
                If you did not request this, you can safely ignore this email.
                Your password has not been changed.
            </p>
        </div>
    </body>
    </html>
    ";

    return mail($to, $subject, $body, $headers);
}
