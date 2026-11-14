(function () {
  function showToast(msg) {
    const el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("show");
    window.setTimeout(() => el.classList.remove("show"), 2200);
  }

  const navToggle = document.getElementById("nav-toggle");
  const navLinks = document.getElementById("nav-links");
  if (navToggle && navLinks) {
    navToggle.addEventListener("click", () => {
      const open = navLinks.classList.toggle("open");
      navToggle.setAttribute("aria-expanded", String(open));
    });
  }

  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const text = btn.getAttribute("data-copy") || "";
      try {
        await navigator.clipboard.writeText(text);
        showToast("Copied to clipboard");
      } catch (err) {
        showToast("Copy failed: " + (err && err.message ? err.message : "clipboard unavailable"));
      }
    });
  });

  const presetEl = document.getElementById("studio-preset");
  const textEl = document.getElementById("studio-text");
  const runBtn = document.getElementById("studio-run");

  const presets = {
    ussd: "URGENT: Dial *21*0772112233# immediately to prevent SIM deactivation or Mobile Money suspension.",
    homograph: "Verify your Stanbic account at https://xn--pple-43d.com/login?token=secret123 before 5pm.",
    reversal: "You received UGX 450,000 by mistake. Send back UGX 450,000 and enter your MoMo PIN 4821.",
    benign: "Team meeting moved to 14:00 EAT in Kampala office."
  };

  function analyzeSample() {
    if (!textEl) return;
    const raw = textEl.value || "";
    const lower = raw.toLowerCase();
    const hasUssd = /\*(21|61|62|67|165|185)\*/.test(raw);
    const hasPuny = /xn--/.test(lower);
    const hasPin = /(pin|otp|password|token)/.test(lower);
    const hasUrgent = /(urgent|immediately|suspend|verify)/.test(lower);
    const score = Math.min(100, (hasUssd ? 45 : 0) + (hasPuny ? 40 : 0) + (hasPin ? 25 : 0) + (hasUrgent ? 20 : 0));
    const redacted = raw.replace(/\b0\d{9}\b/g, "[REDACTED_PHONE]").replace(/\b\d{4,6}\b/g, "[REDACTED_PIN]");

    const outEl = document.getElementById("studio-output");
    if (outEl) {
      outEl.textContent = JSON.stringify({
        advisory_score: score,
        risk_tier: score >= 70 ? "HIGH" : score >= 35 ? "ELEVATED" : "LOW_SIGNALS",
        network_fetches_performed: 0,
        findings: {
          mobile_money_ussd_fraud: hasUssd ? 45 : 0,
          domain_url_deception: hasPuny ? 40 : 0,
          credential_harvesting: hasPin ? 25 : 0,
          social_engineering_urgency: hasUrgent ? 20 : 0
        },
        remediation: hasUssd ? "Dial ##002# to cancel call/SMS forwarding" : "Never share PINs or OTPs",
        redacted_excerpt: redacted
      }, null, 2);
    }
  }

  if (presetEl && textEl) {
    presetEl.addEventListener("change", () => {
      textEl.value = presets[presetEl.value] || presets.ussd;
      analyzeSample();
    });
  }
  if (runBtn) {
    runBtn.addEventListener("click", analyzeSample);
    analyzeSample();
  }
})();
