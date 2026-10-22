/*
 * WooCommerce block checkout: the order is placed with a Store API request,
 * not a form submit. Right before that request, ask doorkeep for a fresh
 * token (tokens are short-lived and single-use) and send it as the
 * X-Doorkeep-Response header; the plugin verifies it on the server.
 */
(function () {
  if (!window.wp || !wp.apiFetch) return;
  wp.apiFetch.use(function (options, next) {
    var target = String(options.path || options.url || "");
    var post = String(options.method || "GET").toUpperCase() === "POST";
    if (!post || target.indexOf("/wc/store/v1/checkout") === -1) return next(options);
    if (!window.doorkeep) return next(options); // the server refuses it without a token
    return window.doorkeep.execute(undefined, { action: "checkout" }).then(
      function (token) {
        options.headers = Object.assign({}, options.headers, { "X-Doorkeep-Response": token });
        return next(options);
      },
      function () { return next(options); }
    );
  });
})();
