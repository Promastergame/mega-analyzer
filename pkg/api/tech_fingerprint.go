package api

// ─────────────────────────────────────────────────────────────────────────────
// TECH FINGERPRINT ENGINE (WhatWeb-style)
//
// Detects the technology stack of a website from four evidence sources:
//   1. HTTP response headers (Server, X-Powered-By, dedicated headers)
//   2. Cookie names (PHPSESSID, laravel_session, BITRIX_SM_*, _ga, _ym_uid…)
//   3. <meta name="generator"> content
//   4. HTML body patterns (asset paths, JS globals, CDN hosts)
//
// Each signature carries a category, an optional version extractor and a
// confidence level ("certain" = dedicated marker, "probable" = heuristic
// pattern that can appear on unrelated pages).
// ─────────────────────────────────────────────────────────────────────────────

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const (
	confCertain  = "certain"
	confProbable = "probable"
)

// techSignature is one declarative detection rule. All fields are optional;
// the matcher checks headers → cookies → generator → body in that order and
// stops at the first hit.
type techSignature struct {
	Name       string
	Category   string
	Confidence string            // defaults to "certain"
	Headers    map[string]string // header (any case) → substring, "" = presence only
	Cookies    []string          // cookie name prefixes, case-insensitive
	Generator  []string          // substrings to match inside <meta name=generator>
	Body       []string          // regex patterns matched against the HTML body
	VersionRe  string            // body regex whose capture group 1 is the version
}

// TechDetection is a single detected technology.
type TechDetection struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Version    string `json:"version,omitempty"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence"`
}

type compiledTechSig struct {
	techSignature
	bodyRes   []*regexp.Regexp
	versionRe *regexp.Regexp
	genSubstr []string
}

var rawTechSignatures = []techSignature{
	// ── Web servers ──────────────────────────────────────────────────────────
	{Name: "nginx", Category: "Web server", Headers: map[string]string{"Server": "nginx"}},
	{Name: "Apache", Category: "Web server", Headers: map[string]string{"Server": "apache"}},
	{Name: "Microsoft IIS", Category: "Web server", Headers: map[string]string{"Server": "microsoft-iis"}},
	{Name: "LiteSpeed", Category: "Web server", Headers: map[string]string{"Server": "litespeed"}},
	{Name: "OpenResty", Category: "Web server", Headers: map[string]string{"Server": "openresty"}},
	{Name: "Caddy", Category: "Web server", Headers: map[string]string{"Server": "caddy"}},
	{Name: "Apache Tomcat", Category: "Web server", Headers: map[string]string{"Server": "coyote", "X-Powered-By": "jsp"}},
	{Name: "Jetty", Category: "Web server", Headers: map[string]string{"Server": "jetty"}},
	{Name: "Gunicorn", Category: "Web server / WSGI", Headers: map[string]string{"Server": "gunicorn", "Via": "gunicorn"}},
	{Name: "Deno", Category: "Web server", Headers: map[string]string{"Server": "deno/"}},
	{Name: "Vercel", Category: "Hosting", Headers: map[string]string{"Server": "vercel", "X-Vercel-Id": ""}},
	{Name: "Pantheon", Category: "Hosting", Headers: map[string]string{"X-Pantheon-Environment": ""}},

	// ── Languages / runtimes ─────────────────────────────────────────────────
	{Name: "PHP", Category: "Language", Headers: map[string]string{"X-Powered-By": "php"}},
	{Name: "ASP.NET", Category: "Language", Headers: map[string]string{"X-Powered-By": "asp.net", "X-AspNet-Version": ""}},
	{Name: "Classic ASP", Category: "Language", Cookies: []string{"ASPSESSIONID"}, Confidence: confProbable},
	{Name: "Java", Category: "Language", Cookies: []string{"JSESSIONID"}},
	{Name: "Servlet API", Category: "Language", Headers: map[string]string{"X-Powered-By": "servlet"}, Confidence: confProbable},

	// ── Frameworks ───────────────────────────────────────────────────────────
	{Name: "Laravel", Category: "Framework", Cookies: []string{"laravel_session", "laravel_token"},
		Body: []string{`csrf-token"[^>]*content="[^"]*"`, `laravel\.mix\.js`}},
	{Name: "Django", Category: "Framework", Body: []string{`csrfmiddlewaretoken`, `django\.js`}},
	{Name: "Express.js", Category: "Framework", Headers: map[string]string{"X-Powered-By": "express"}},
	{Name: "Ruby on Rails", Category: "Framework", Body: []string{`csrf-param`, `data-turbolinks`, `turbolinks-`}, Confidence: confProbable},
	{Name: "Spring Boot", Category: "Framework", Headers: map[string]string{"X-Application-Context": ""}},
	{Name: "CodeIgniter", Category: "Framework", Cookies: []string{"ci_session"}},
	{Name: "CakePHP", Category: "Framework", Cookies: []string{"CAKEPHP"}},
	{Name: "ASP.NET MVC", Category: "Framework", Headers: map[string]string{"X-Aspnetmvc-Version": ""}},
	{Name: "SvelteKit", Category: "Framework", Body: []string{`__sveltekit_`, `/src/app/environment`}},
	{Name: "Astro", Category: "Framework", Body: []string{`astro-island`, `/_astro/`}},
	{Name: "Vite", Category: "Build tool", Body: []string{`__vite__`, `/@vite/client`, `/@react-refresh`, `supports\("modulepreload"\)\)return`}},
	{Name: "Remix", Category: "Framework", Body: []string{`__remixContext`, `window\.__remixManifest`}},
	{Name: "Eleventy", Category: "Static site generator", Generator: []string{"eleventy"}, Confidence: confProbable},

	// ── JS frameworks / libraries ────────────────────────────────────────────
	{Name: "React", Category: "JS framework", Body: []string{`data-reactroot`, `__REACT_DEVTOOLS`, `_reactListening`, `react-dom`, `data-reactid`, `react\.transitional\.element`}},
	{Name: "Next.js", Category: "JS framework", Body: []string{`__NEXT_DATA__`, `/_next/static/`}},
	{Name: "Vue.js", Category: "JS framework", Body: []string{`window\.__vue__`, `data-v-[0-9a-f]{6,8}["']`, `<nuxt-link`, `vue\.runtime`}, VersionRe: `vue(?:@|/|-)(\d+(?:\.\d+)+)`},
	{Name: "Nuxt.js", Category: "JS framework", Body: []string{`window\.__NUXT__`, `/_nuxt/`, `__NUXT_DATA__`}},
	{Name: "Angular", Category: "JS framework", Body: []string{`ng-version="`, `ng-app=`}, VersionRe: `ng-version="(\d+(?:\.\d+)+)"`},
	{Name: "Svelte", Category: "JS framework", Body: []string{`class="svelte-[0-9a-z]{6}"`}, Confidence: confProbable},
	{Name: "Gatsby", Category: "JS framework", Body: []string{`___gatsby`, `gatsby-image`}},
	{Name: "Alpine.js", Category: "JS framework", Body: []string{`alpinejs`, `x-data="`}, Confidence: confProbable},
	{Name: "htmx", Category: "JS framework", Body: []string{`htmx\.org`, `hx-get="`, `hx-post="`}, Confidence: confProbable},
	{Name: "jQuery", Category: "JS library", Body: []string{`jquery(\.min)?\.js`, `jquery-\d`},
		VersionRe: `jquery(?:[-/]?(\d+(?:\.\d+)+))?(?:\.min)?\.js(?:\?ver=(\d+(?:\.\d+)+))?`},
	{Name: "jQuery UI", Category: "JS library", Body: []string{`jquery-ui(\.min)?\.(js|css)`, `jquery\.ui\.`}},
	{Name: "Lodash", Category: "JS library", Body: []string{`lodash(\.min)?\.js`}, Confidence: confProbable},
	{Name: "Moment.js", Category: "JS library", Body: []string{`moment(-with-locales)?(\.min)?\.js`}, Confidence: confProbable},
	{Name: "Modernizr", Category: "JS library", Body: []string{`modernizr(\.min)?\.js`}, Confidence: confProbable},
	{Name: "Leaflet", Category: "JS library / maps", Body: []string{`leaflet(\.min)?\.(js|css)`, `leaflet\.js`}},
	{Name: "Three.js", Category: "JS library", Body: []string{`three(\.min|\.module)?\.js`}, Confidence: confProbable},
	{Name: "Chart.js", Category: "JS library", Body: []string{`chart(\.umd)?\.min\.js`, `chartjs`}},
	{Name: "GSAP", Category: "JS library", Body: []string{`gsap(/|min\.js|@\d)`}, Confidence: confProbable},
	{Name: "Swiper", Category: "JS library", Body: []string{`swiper(-bundle)?(\.min)?\.(js|css)`}},
	{Name: "Slick carousel", Category: "JS library", Body: []string{`slick(\.min)?\.(js|css)`, `slick-carousel`}, Confidence: confProbable},
	{Name: "Video.js", Category: "JS library", Body: []string{`video(\.min)?\.js`, `video-js`}},
	{Name: "JW Player", Category: "JS library", Body: []string{`jwplayer`, `jw-player`}},
	{Name: "Plyr", Category: "JS library", Body: []string{`plyr(\.min)?\.(js|css)`}},

	// ── CSS / UI ─────────────────────────────────────────────────────────────
	{Name: "Bootstrap", Category: "CSS framework", Body: []string{`bootstrap(\.min)?\.css`, `bootstrap@\d`, `bootstrap/\d`}, VersionRe: `bootstrap(?:@|/|-)(\d+(?:\.\d+)+)`},
	{Name: "Tailwind CSS", Category: "CSS framework", Body: []string{`tailwindcss`, `tailwind\.config`, `/_tailwind/`, `cdn\.tailwindcss\.com`}},
	{Name: "Font Awesome", Category: "CSS / icons", Body: []string{`font-?awesome[/@\s-]v?\d`, `fontawesome`, `fa-solid`, `fa-[\w-]+"`}, VersionRe: `font-?awesome[/@\s-]v?(\d+(?:\.\d+)+)`},
	{Name: "Google Fonts", Category: "Font service", Body: []string{`fonts\.(googleapis|gstatic)\.com`}},
	{Name: "Material Design Icons", Category: "CSS / icons", Body: []string{`material-icons`, `materialdesignicons`}},
	{Name: "Bulma", Category: "CSS framework", Body: []string{`bulma(\.min)?\.css`, `bulma@`}, Confidence: confProbable},
	{Name: "Foundation", Category: "CSS framework", Body: []string{`foundation(\.min)?\.css`, `foundation@`}, Confidence: confProbable},

	// ── CMS ──────────────────────────────────────────────────────────────────
	{Name: "WordPress", Category: "CMS",
		Generator: []string{"wordpress"},
		Cookies:   []string{"wp-settings-", "wordpress_logged_in", "wp-postpass"},
		Body:      []string{`/wp-content/`, `/wp-includes/`, `/wp-json/`, `wp-emoji`},
		VersionRe: `wp-includes/[^"']*\?ver=(\d+(?:\.\d+)+)`},
	{Name: "Drupal", Category: "CMS",
		Generator: []string{"drupal"},
		Headers:   map[string]string{"X-Drupal-Cache": "", "X-Generator": "drupal"},
		Body:      []string{`Drupal\.settings`, `/sites/default/files/`, `/core/assets/`, `drupal\.org`}},
	{Name: "Joomla", Category: "CMS",
		Generator: []string{"joomla"},
		Body:      []string{`/components/com_`, `/media/jui/`, `Joomla!`}},
	{Name: "1C-Bitrix", Category: "CMS",
		Cookies: []string{"BITRIX_SM_"},
		Body:    []string{`/bitrix/`, `BX\.message`, `bxAjax`}},
	{Name: "DLE (DataLife Engine)", Category: "CMS", Generator: []string{"datalife engine", "dle-news"}, Body: []string{`/engine/classes/`, `dle_css`, `dle_js`}, Confidence: confProbable},
	{Name: "MODX", Category: "CMS", Generator: []string{"modx"}, Body: []string{`/assets/components/`, `modx\.js`}, Confidence: confProbable},
	{Name: "OpenCart", Category: "E-commerce", Body: []string{`index\.php\?route=`, `/catalog/view/theme/`}},
	{Name: "PrestaShop", Category: "E-commerce", Body: []string{`prestashop`, `/modules/ps_`}},
	{Name: "Magento", Category: "E-commerce", Body: []string{`Magento`, `mage/requirejs`, `requirejs-config`}},
	{Name: "WooCommerce", Category: "E-commerce", Body: []string{`/plugins/woocommerce`, `woocommerce`}},
	{Name: "Shopify", Category: "E-commerce platform", Headers: map[string]string{"X-ShopId": "", "X-Shopify-Stage": ""}, Body: []string{`cdn\.shopify\.com`, `Shopify\.theme`}},
	{Name: "Ghost", Category: "CMS", Body: []string{`ghost-sdk`, `/ghost/api/`, `content/images/size`}},
	{Name: "Craft CMS", Category: "CMS", Body: []string{`craftcms`, `/cpresources/`}},
	{Name: "TYPO3", Category: "CMS", Generator: []string{"typo3"}, Body: []string{`/typo3/`, `typo3temp`}},
	{Name: "Concrete CMS", Category: "CMS", Generator: []string{"concrete5", "concrete cms"}},
	{Name: "Grav", Category: "CMS", Generator: []string{"grav"}},
	{Name: "Hugo", Category: "Static site generator", Generator: []string{"hugo"}},
	{Name: "Jekyll", Category: "Static site generator", Generator: []string{"jekyll"}, Body: []string{`jekyll`}},
	{Name: "Hexo", Category: "Static site generator", Generator: []string{"hexo"}},

	// ── Website builders / platforms ─────────────────────────────────────────
	{Name: "Wix", Category: "Website builder", Body: []string{`static\.wixstatic\.com`, `wix-code`, `_next/static.wix`}},
	{Name: "Squarespace", Category: "Website builder", Body: []string{`squarespace`, `static1\.squarespace`}},
	{Name: "Tilda", Category: "Website builder", Body: []string{`static\.tilda\.cc`, `/tilda-blocks/`, `tilda-block`}},
	{Name: "Webflow", Category: "Website builder", Body: []string{`webflow`, `w-mod-js`, `assets\.website-files\.com`}},
	{Name: "uCoz", Category: "Website builder", Body: []string{`ucoz`, `/ucoz-`, `ucoban`}},
	{Name: "Nethouse", Category: "Website builder", Body: []string{`nethouse\.ru`, `nethouse-`}, Confidence: confProbable},
	{Name: "GitHub Pages", Category: "Hosting", Headers: map[string]string{"Server": "github"}, Body: []string{`github\.io/`}, Confidence: confProbable},

	// ── Forums ───────────────────────────────────────────────────────────────
	{Name: "phpBB", Category: "Forum", Body: []string{`phpbb`, `/styles/prosilver/`}},
	{Name: "vBulletin", Category: "Forum", Body: []string{`vbulletin`, `vB_Editor`}},
	{Name: "XenForo", Category: "Forum", Body: []string{`xenforo`, `/js/xf/`}},
	{Name: "Discourse", Category: "Forum", Body: []string{`discourse`, `/cdn-discourse/`}},
	{Name: "Flarum", Category: "Forum", Body: []string{`flarum`}},
	{Name: "MediaWiki", Category: "Wiki", Body: []string{`mediawiki`, `/w/index\.php\?title=`}},
	{Name: "DokuWiki", Category: "Wiki", Generator: []string{"dokuwiki"}},

	// ── Analytics / marketing ────────────────────────────────────────────────
	{Name: "Google Analytics", Category: "Analytics", Body: []string{`google-analytics\.com`, `gtag/js`, `googletagmanager\.com/gtag`}, Cookies: []string{"_ga", "_gid"}},
	{Name: "Google Tag Manager", Category: "Tag manager", Body: []string{`googletagmanager\.com/gtm\.js`, `dataLayer`}},
	{Name: "Yandex Metrika", Category: "Analytics", Body: []string{`mc\.yandex\.ru`, `metrika/tag\.js`, `ym\(\d+,`}, Cookies: []string{"_ym_uid", "_ym_isad", "yandexuid"}},
	{Name: "Matomo", Category: "Analytics", Body: []string{`matomo\.js`, `piwik\.js`}},
	{Name: "Facebook Pixel", Category: "Advertising", Body: []string{`connect\.facebook\.net/.*/fbevents\.js`, `fbq\('init'`}, Cookies: []string{"_fbp"}},
	{Name: "VK Pixel", Category: "Advertising", Body: []string{`vk\.com/rtrg`, `top-fwz1\.mail\.ru`}},
	{Name: "Yandex Direct", Category: "Advertising", Body: []string{`an\.yandex\.ru`, `yandex\.ru/ads/system`, `yaContextCb`}},
	{Name: "Google AdSense", Category: "Advertising", Body: []string{`adsbygoogle`, `pagead2\.googlesyndication`}},
	{Name: "Google Ads Remarketing", Category: "Advertising", Body: []string{`googleadservices`, `google_conversion`}, Confidence: confProbable},
	{Name: "Doubleclick", Category: "Advertising", Body: []string{`doubleclick\.net`}, Cookies: []string{"IDE="}},
	{Name: "Taboola", Category: "Advertising", Body: []string{`taboola`}},
	{Name: "Hotjar", Category: "Analytics", Body: []string{`static\.hotjar\.com`, `hjSiteSettings`}},
	{Name: "Mixpanel", Category: "Analytics", Body: []string{`mixpanel`, `cdn\.mxpnl`}},
	{Name: "Amplitude", Category: "Analytics", Body: []string{`cdn\.amplitude\.com`, `amplitude\.init`}},
	{Name: "Segment", Category: "Analytics", Body: []string{`cdn\.segment\.com`, `analytics\.load`}},
	{Name: "Microsoft Clarity", Category: "Analytics", Body: []string{`clarity\.ms`}},
	{Name: "Plausible", Category: "Analytics", Body: []string{`plausible\.io`}},
	{Name: "HubSpot", Category: "Marketing", Body: []string{`hs-scripts\.com`, `hubspot`}},
	{Name: "Mailchimp", Category: "Email marketing", Body: []string{`list-manage\.com`, `chimpstatic`}},
	{Name: "Roistat", Category: "Marketing", Body: []string{`roistat`}},
	{Name: "Sentry", Category: "Error tracking", Body: []string{`sentry(-cdn|\.io|\.onload)`}},
	{Name: "New Relic", Category: "Monitoring", Body: []string{`nr-data\.net`, `newrelic`}},
	{Name: "OneTrust", Category: "Cookie consent", Body: []string{`onetrust`, `optanon`}},
	{Name: "Cookiebot", Category: "Cookie consent", Body: []string{`cookiebot`, `consent\.cookiebot`}},
	{Name: "Transcend Consent", Category: "Cookie consent", Body: []string{`transcend-cdn\.com`, `airgap\.js`}},
	{Name: "Statsig", Category: "Feature flags", Body: []string{`statsig`}, Confidence: confProbable},
	{Name: "Tawk.to", Category: "Live chat", Body: []string{`tawk\.to`, `tawkto`}},
	{Name: "JivoSite", Category: "Live chat", Body: []string{`jivo\.(ru|site|sdk)`, `jivo_container`, `code\.jivosite`}},
	{Name: "Intercom", Category: "Live chat", Body: []string{`intercom`, `intercomcdn`}},
	{Name: "Crisp", Category: "Live chat", Body: []string{`crisp\.chat`}},
	{Name: "LiveChat", Category: "Live chat", Body: []string{`livechatinc`, `livechat`}, Confidence: confProbable},

	// ── CDN / WAF / infrastructure ───────────────────────────────────────────
	{Name: "Cloudflare", Category: "CDN / WAF", Headers: map[string]string{"Cf-Ray": "", "Server": "cloudflare"}, Body: []string{`cloudflareinsights`, `challenges\.cloudflare\.com`}},
	{Name: "Fastly", Category: "CDN", Headers: map[string]string{"X-Served-By": "cache-"}},
	{Name: "Akamai", Category: "CDN", Headers: map[string]string{"X-Check-Cacheable": "", "Server": "akamai"}},
	{Name: "AWS CloudFront", Category: "CDN", Headers: map[string]string{"X-Amz-Cf-Id": "", "Via": "cloudfront"}, Body: []string{`d[0-9a-z]+\.cloudfront\.net`}},
	{Name: "AWS Elastic Load Balancer", Category: "Load balancer", Headers: map[string]string{"X-Amzn-Trace-Id": ""}},
	{Name: "Azure Front Door", Category: "CDN", Headers: map[string]string{"X-Azure-Ref": ""}},
	{Name: "Varnish Cache", Category: "Cache", Headers: map[string]string{"X-Varnish": ""}},
	{Name: "Sucuri WAF", Category: "WAF", Headers: map[string]string{"X-Sucuri-Id": "", "Server": "sucuri"}},
	{Name: "DDoS-Guard", Category: "WAF", Headers: map[string]string{"Server": "ddos-guard"}, Body: []string{`ddos-guard`}},
	{Name: "bunny.net CDN", Category: "CDN", Body: []string{`bunny\.net`, `bunnycdn`}},
	{Name: "jsDelivr CDN", Category: "CDN", Body: []string{`cdn\.jsdelivr\.net`}},
	{Name: "unpkg CDN", Category: "CDN", Body: []string{`unpkg\.com`}},
	{Name: "cdnjs", Category: "CDN", Body: []string{`cdnjs\.cloudflare\.com`}},

	// ── Payments ─────────────────────────────────────────────────────────────
	{Name: "Stripe", Category: "Payment", Body: []string{`js\.stripe\.com`, `checkout\.stripe\.com`, `stripe\.com/v3`}},
	{Name: "PayPal", Category: "Payment", Body: []string{`paypal\.com/sdk`, `paypalobjects`, `paypal\.min\.js`}},
	{Name: "YooKassa", Category: "Payment", Body: []string{`yookassa`}},
	{Name: "CloudPayments", Category: "Payment", Body: []string{`cloudpayments`}},
	{Name: "Tinkoff Business API", Category: "Payment", Body: []string{`tinkoff\.ru/rw`, `securepay\.tinkoff`}, Confidence: confProbable},

	// ── Security / captcha ───────────────────────────────────────────────────
	{Name: "reCAPTCHA", Category: "Captcha", Body: []string{`recaptcha/api\.js`, `g-recaptcha`, `grecaptcha`}},
	{Name: "hCaptcha", Category: "Captcha", Body: []string{`hcaptcha\.com`, `h-captcha`}},
	{Name: "Cloudflare Turnstile", Category: "Captcha", Body: []string{`challenges\.cloudflare\.com/turnstile`, `cf-turnstile`}},
	{Name: "SEOPress", Category: "SEO plugin", Body: []string{`seopress`}, Confidence: confProbable},
	{Name: "Yoast SEO", Category: "SEO plugin", Body: []string{`yoast`, `wpseo`}, Confidence: confProbable},
	{Name: "Rank Math SEO", Category: "SEO plugin", Body: []string{`rank-math`}, Confidence: confProbable},
	{Name: "All in One SEO", Category: "SEO plugin", Body: []string{`aioseo`}, Confidence: confProbable},

	// ── WP page builders (depend on WordPress assets) ────────────────────────
	{Name: "Elementor", Category: "Page builder", Body: []string{`elementor`, `/uploads/elementor/`}},
	{Name: "WPBakery", Category: "Page builder", Body: []string{`wpbakery`, `js_composer`, `vc_row`}},
	{Name: "Divi Builder", Category: "Page builder", Body: []string{`et_pb_`, `divi-builder`}},
	{Name: "Contact Form 7", Category: "WordPress plugin", Body: []string{`contact-form-7`}},
	{Name: "WooCommerce Blocks", Category: "E-commerce", Body: []string{`wc-blocks`, `woocommerce-blocks`}, Confidence: confProbable},

	// ── Auth / backend services ──────────────────────────────────────────────
	{Name: "Auth0", Category: "Authentication", Body: []string{`auth0\.com`, `cdn\.auth0`}},
	{Name: "Firebase", Category: "Backend platform", Body: []string{`firebase`, `firebaseio\.com`, `googleapis\.com/firebase`}},
	{Name: "Supabase", Category: "Backend platform", Body: []string{`supabase`}},
	{Name: "GraphQL", Category: "API", Body: []string{`/graphql`, `graphql\.js`}, Confidence: confProbable},

	// ── Maps ─────────────────────────────────────────────────────────────────
	{Name: "Google Maps", Category: "Maps", Body: []string{`maps\.googleapis\.com`, `maps\.google\.com/maps`}},
	{Name: "Yandex Maps", Category: "Maps", Body: []string{`api-maps\.yandex`, `yastatic\.net/maps`}},
	{Name: "Mapbox", Category: "Maps", Body: []string{`mapbox`, `api\.mapbox\.com`}},

	// ── Misc ─────────────────────────────────────────────────────────────────
	{Name: "RSS feed", Category: "Syndication", Body: []string{`application/rss\+xml`}, Confidence: confProbable},
	{Name: "Open Graph", Category: "Meta protocol", Body: []string{`property="og:`}, Confidence: confProbable},
	{Name: "Twitter Cards", Category: "Meta protocol", Body: []string{`name="twitter:`}, Confidence: confProbable},
	{Name: "Schema.org", Category: "Structured data", Body: []string{`schema\.org`, `application/ld\+json`}, Confidence: confProbable},
	{Name: "PWA / Web App Manifest", Category: "Progressive web app", Body: []string{`rel="manifest"`, `rel='manifest'`}},
	{Name: "Service Worker", Category: "Progressive web app", Body: []string{`serviceWorker\.register`}, Confidence: confProbable},
	{Name: "Google Workspace verification", Category: "Misc", Body: []string{`google-site-verification`}, Confidence: confProbable},
	{Name: "Yandex Webmaster verification", Category: "Misc", Body: []string{`yandex-verification`}, Confidence: confProbable},

	// ── Domain parking (registrar placeholders) ──────────────────────────────
	{Name: "REG.RU Parking", Category: "Domain parking", Body: []string{`b-parking__`, `parking-rdap`, `b-page_type_parking`}, Confidence: confProbable},
	{Name: "GoDaddy Parking", Category: "Domain parking", Body: []string{`godaddy\.com/domains/search`, `parked-content`}, Confidence: confProbable},
	{Name: "Sedo Parking", Category: "Domain parking", Body: []string{`sedoparking\.com`}, Confidence: confProbable},
	{Name: "Bodis Parking", Category: "Domain parking", Body: []string{`bodis\.com`}, Confidence: confProbable},
}

// compiledTechSignatures is built once at package init.
var compiledTechSignatures = compileTechSignatures(rawTechSignatures)

func compileTechSignatures(raw []techSignature) []compiledTechSig {
	out := make([]compiledTechSig, 0, len(raw))
	for _, sig := range raw {
		c := compiledTechSig{techSignature: sig}
		if c.Confidence == "" {
			c.Confidence = confCertain
		}
		for _, p := range sig.Body {
			if re, err := regexp.Compile("(?i)" + p); err == nil {
				c.bodyRes = append(c.bodyRes, re)
			}
		}
		if sig.VersionRe != "" {
			if re, err := regexp.Compile("(?i)" + sig.VersionRe); err == nil {
				c.versionRe = re
			}
		}
		c.genSubstr = sig.Generator
		out = append(out, c)
	}
	return out
}

var techVersionRe = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)

// extractVersion pulls the first X.Y[.Z] number out of a product string like
// "nginx/1.24.0" or "WordPress 6.4.3".
func extractVersion(s string) string {
	return techVersionRe.FindString(s)
}

var (
	htmlTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.{1,300}?)</title>`)
	metaTagRe   = regexp.MustCompile(`(?is)<meta\s+[^>]*>`)
	metaNameRe  = regexp.MustCompile(`(?i)name\s*=\s*["']?generator["']?`)
	metaContent = regexp.MustCompile(`(?i)content\s*=\s*["']([^"']{1,200})["']`)
)

// extractPageTitle returns the <title> text (trimmed, whitespace-collapsed) or "".
func extractPageTitle(body string) string {
	m := htmlTitleRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	title := strings.Join(strings.Fields(stripTags(m[1])), " ")
	if len(title) > 200 {
		title = title[:200] + "…"
	}
	return title
}

func stripTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// extractGenerator returns the content of <meta name="generator" ...>.
func extractGenerator(body string) string {
	for _, tag := range metaTagRe.FindAllString(body, 50) {
		if metaNameRe.MatchString(tag) {
			if m := metaContent.FindStringSubmatch(tag); m != nil {
				return strings.TrimSpace(m[1])
			}
		}
	}
	return ""
}

// fingerprintSite runs every signature against the collected evidence.
// headers/cookies may be nil; body may be empty (header-only fingerprinting).
func fingerprintSite(headers http.Header, cookies []*http.Cookie, body string) []TechDetection {
	// Lower-cased header view for case-insensitive lookups.
	hdrs := make(map[string]string, len(headers))
	for k, v := range headers {
		hdrs[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	cookieNames := make([]string, 0, len(cookies))
	for _, c := range cookies {
		cookieNames = append(cookieNames, strings.ToLower(c.Name))
	}

	generator := ""
	if body != "" {
		generator = strings.ToLower(extractGenerator(body))
	}

	var detected []TechDetection
	seen := map[string]bool{}

	for _, sig := range compiledTechSignatures {
		if seen[sig.Name] {
			continue
		}
		if ev, ver, ok := matchTechSig(sig, hdrs, cookieNames, generator, body); ok {
			seen[sig.Name] = true
			detected = append(detected, TechDetection{
				Name:       sig.Name,
				Category:   sig.Category,
				Version:    ver,
				Confidence: sig.Confidence,
				Evidence:   ev,
			})
		}
	}
	return detected
}

func matchTechSig(sig compiledTechSig, hdrs map[string]string, cookieNames []string, generator, body string) (evidence, version string, ok bool) {
	// 1. Headers
	for h, needle := range sig.Headers {
		val, present := hdrs[strings.ToLower(h)]
		if !present {
			continue
		}
		if needle == "" || strings.Contains(strings.ToLower(val), strings.ToLower(needle)) {
			ev := fmt.Sprintf("header %s: %s", h, truncate(evVal(val)))
			if needle != "" {
				version = extractVersion(val)
			}
			return ev, version, true
		}
	}
	// 2. Cookies
	for _, prefix := range sig.Cookies {
		for _, cn := range cookieNames {
			if strings.HasPrefix(cn, strings.ToLower(prefix)) {
				return "cookie " + cn, "", true
			}
		}
	}
	// 3. <meta name="generator">
	if generator != "" {
		for _, sub := range sig.genSubstr {
			if strings.Contains(generator, sub) {
				gen := extractGenerator(body)
				ver := extractVersion(gen)
				return "<meta name=\"generator\">: " + truncate(gen), ver, true
			}
		}
	}
	// 4. Body patterns
	if body != "" {
		for _, re := range sig.bodyRes {
			if m := re.FindString(body); m != "" {
				ev := "body: '" + truncate(m) + "'"
				if sig.versionRe != nil {
					if vm := sig.versionRe.FindStringSubmatch(body); vm != nil {
						// Take the first non-empty capture group so patterns can
						// offer several alternatives (e.g. jQuery path vs ?ver=).
						for _, g := range vm[1:] {
							if g != "" {
								ev += fmt.Sprintf(" (version %s)", g)
								return ev, g, true
							}
						}
					}
				}
				return ev, "", true
			}
		}
	}
	return "", "", false
}

func evVal(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

func truncate(s string) string {
	if len(s) > 70 {
		return s[:70] + "…"
	}
	return s
}

// techSummary builds a human sentence naming the key stack pieces, e.g.
// "WordPress 6.4 · PHP 8.1 · nginx 1.24 · Bootstrap 5".
func techSummary(dets []TechDetection) string {
	prio := []string{"CMS", "E-commerce", "E-commerce platform", "Website builder", "Forum", "Wiki",
		"JS framework", "Framework", "Build tool", "Language", "Web server", "CDN / WAF"}
	picked := make([]string, 0, 5)
	used := map[string]bool{}
	for _, cat := range prio {
		for _, d := range dets {
			if d.Category == cat && !used[cat] && d.Confidence == confCertain {
				label := d.Name
				if d.Version != "" {
					label += " " + d.Version
				}
				picked = append(picked, label)
				used[cat] = true
				break
			}
		}
		if len(picked) >= 5 {
			break
		}
	}
	return strings.Join(picked, " · ")
}
