(function () {
  function setRequired(input, required) {
    if (!input) return;
    if (required) {
      input.setAttribute("required", "required");
      return;
    }
    input.removeAttribute("required");
  }

  function toggleGroup(group, show) {
    if (!group) return;
    group.hidden = !show;
  }

  function normalize(value) {
    return (value || "").trim().toLowerCase();
  }

  function isXSlug(value) {
    var v = normalize(value);
    return v === "x" || v === "xcom" || v === "x.com" || v === "twitter";
  }

  var presets = {
    google: {
      name: "Google",
      slug: "google",
      icon: "google",
      providerType: "oidc",
      issuerURL: "https://accounts.google.com",
      authorizationURL: "",
      tokenURL: "",
      userinfoURL: "",
      scopes: "openid email profile",
    },
    xcom: {
      name: "X.com",
      slug: "x",
      icon: "x",
      providerType: "oauth2",
      issuerURL: "",
      authorizationURL: "https://x.com/i/oauth2/authorize",
      tokenURL: "https://api.x.com/2/oauth2/token",
      userinfoURL: "https://api.x.com/2/users/me?user.fields=id,name,username,profile_image_url",
      scopes: "users.read",
    },
  };

  function bindForm(form) {
    var providerType = form.querySelector('select[name="provider_type"]');
    if (!providerType) return;

    var oidcGroup = form.querySelector('[data-provider-group="oidc"]');
    var oauth2Group = form.querySelector('[data-provider-group="oauth2"]');

    var nameInput = form.querySelector('input[name="name"]');
    var slugInput = form.querySelector('input[name="slug"]');
    var iconInput = form.querySelector('input[name="icon"]');
    var issuer = form.querySelector('input[name="issuer_url"]');
    var authorization = form.querySelector('input[name="authorization_url"]');
    var token = form.querySelector('input[name="token_url"]');
    var userinfo = form.querySelector('input[name="userinfo_url"]');
    var scopes = form.querySelector('input[name="scopes"]');
    var scopeHint = form.querySelector("[data-scope-hint]");
    var presetButtons = form.querySelectorAll("[data-provider-template]");

    function applyProviderMode() {
      var mode = providerType.value === "oauth2" ? "oauth2" : "oidc";
      var isOIDC = mode === "oidc";

      toggleGroup(oidcGroup, isOIDC);
      toggleGroup(oauth2Group, !isOIDC);

      setRequired(issuer, isOIDC);
      setRequired(authorization, !isOIDC);
      setRequired(token, !isOIDC);
      setRequired(userinfo, !isOIDC);

      if (scopeHint) {
        scopeHint.textContent = isOIDC
          ? "OIDC 建议权限范围：openid email profile（必须包含 openid）"
          : "OAuth2 权限范围请按提供商文档填写（例如 users.read）";
      }
      if (scopes && !scopes.value.trim()) {
        scopes.placeholder = isOIDC ? "openid email profile" : "users.read";
      }
    }

    function markActivePreset(presetName) {
      for (var i = 0; i < presetButtons.length; i += 1) {
        var btn = presetButtons[i];
        if (btn.getAttribute("data-provider-template") === presetName) {
          btn.classList.add("active");
        } else {
          btn.classList.remove("active");
        }
      }
    }

    function applyPreset(presetName) {
      var preset = presets[presetName];
      if (!preset) return;

      if (nameInput) nameInput.value = preset.name;
      if (slugInput) slugInput.value = preset.slug;
      if (iconInput) iconInput.value = preset.icon;

      providerType.value = preset.providerType;
      if (issuer) issuer.value = preset.issuerURL;
      if (authorization) authorization.value = preset.authorizationURL;
      if (token) token.value = preset.tokenURL;
      if (userinfo) userinfo.value = preset.userinfoURL;
      if (scopes) scopes.value = preset.scopes;

      applyProviderMode();
      markActivePreset(presetName);
    }

    function detectPreset() {
      var slug = normalize(slugInput ? slugInput.value : form.getAttribute("data-provider-slug"));
      var icon = normalize(iconInput ? iconInput.value : "");
      if (slug === "google" || icon === "google") return "google";
      if (isXSlug(slug) || isXSlug(icon)) return "xcom";
      return "";
    }

    providerType.addEventListener("change", applyProviderMode);
    for (var i = 0; i < presetButtons.length; i += 1) {
      (function (btn) {
        btn.addEventListener("click", function () {
          var presetName = btn.getAttribute("data-provider-template");
          applyPreset(presetName);
        });
      })(presetButtons[i]);
    }

    applyProviderMode();
    markActivePreset(detectPreset());
  }

  var forms = document.querySelectorAll('form[data-provider-form="1"]');
  for (var i = 0; i < forms.length; i += 1) {
    bindForm(forms[i]);
  }
})();
