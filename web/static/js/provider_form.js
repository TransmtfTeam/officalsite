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

  function bindForm(form) {
    var providerType = form.querySelector('select[name="provider_type"]');
    if (!providerType) return;

    var oidcGroup = form.querySelector('[data-provider-group="oidc"]');
    var oauth2Group = form.querySelector('[data-provider-group="oauth2"]');

    var issuer = form.querySelector('input[name="issuer_url"]');
    var authorization = form.querySelector('input[name="authorization_url"]');
    var token = form.querySelector('input[name="token_url"]');
    var userinfo = form.querySelector('input[name="userinfo_url"]');
    var scopes = form.querySelector('input[name="scopes"]');
    var scopeHint = form.querySelector("[data-scope-hint]");

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
          : "OAuth2 建议权限范围：profile email";
      }
      if (scopes && !scopes.value.trim()) {
        scopes.placeholder = isOIDC ? "openid email profile" : "profile email";
      }
    }

    providerType.addEventListener("change", applyProviderMode);
    applyProviderMode();
  }

  var forms = document.querySelectorAll('form[data-provider-form="1"]');
  for (var i = 0; i < forms.length; i += 1) {
    bindForm(forms[i]);
  }
})();
