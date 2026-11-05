"""
CyberGuard AI - Email Analysis Enums and Constants

Centralized definitions for URL categories, verdicts, analysis status,
and domain classification data.
"""

from enum import Enum


# =============================================================================
# URL Categories
# =============================================================================

class URLCategory(str, Enum):
    """Categories for URL classification."""
    NORMAL = "normal"
    TRACKING = "tracking"
    REDIRECT = "redirect"
    SHORTENER = "shortener"
    CDN = "cdn"
    RESOURCE = "resource"
    UNSUBSCRIBE = "unsubscribe"
    AUTHENTICATION = "authentication"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


# =============================================================================
# Analysis Status
# =============================================================================

class AnalysisStatus(str, Enum):
    """Status values for analysis results."""
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    UNKNOWN = "unknown"
    NOT_AVAILABLE = "not_available"
    NOT_CONFIGURED = "not_configured"
    NA = "n/a"
    INFORMATIONAL = "informational"


# =============================================================================
# Verdict Classification
# =============================================================================

class Verdict(str, Enum):
    """Email verdict classification."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


# =============================================================================
# Brand Detection Types
# =============================================================================

class BrandDetectionType(str, Enum):
    """Types of brand detection."""
    BRAND_MENTION = "brand_mention"
    BRAND_IMPERSONATION = "brand_impersonation"


# =============================================================================
# Authentication Results
# =============================================================================

class AuthResult(str, Enum):
    """Email authentication result states."""
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


# =============================================================================
# Known URL Shortener Domains (exact match required)
# =============================================================================

URL_SHORTENER_DOMAINS = {
    # Major shorteners
    "bit.ly", "bitly.com",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd", "v.gd",
    "buff.ly",
    "tiny.cc",
    "lnkd.in",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "short.io",
    "rebrand.ly",
    "bl.ink",
    "soo.gd",
    "s.id",
    "t.ly",
    "qr.ae",
    "adf.ly",
    "bc.vc",
    "j.mp",
    "yourls.org",
    "clck.ru",
    "shortcm.li",
    "han.gl",
    "frama.link",
    "kutt.it",
    "polr.me",
    "1url.com",
    "hyperurl.co",
    "urlzs.com",
    "v.ht",
    "shrtco.de",
    "trib.al",
    "mcaf.ee",
    "dub.sh",
}

# =============================================================================
# Known CDN Domains (legitimate content delivery)
# =============================================================================

CDN_DOMAINS = {
    # Major CDNs
    "cloudflare.com", "cloudflare-dns.com",
    "akamai.net", "akamaized.net", "akamaihd.net",
    "fastly.net", "fastlylb.net",
    "cloudfront.net",
    "edgecastcdn.net",
    "azureedge.net", "azure.com",
    "googleapis.com", "gstatic.com", "ggpht.com",
    "fbcdn.net", "fbsbx.com",
    "twimg.com",
    "cdninstagram.com",
    "amazonaws.com", "awsstatic.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "bootstrapcdn.com",
    "jquery.com",
    "fontawesome.com",
    "fonts.googleapis.com",
    "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com",
    "cdn.jsdelivr.net",
}

# =============================================================================
# Known Tracking Domains (email/marketing tracking)
# =============================================================================

TRACKING_DOMAINS = {
    # Email tracking
    "mailchimp.com", "list-manage.com", "campaign-archive.com",
    "sendgrid.net", "sendgrid.com",
    "constantcontact.com",
    "mailgun.org", "mailgun.com",
    "postmarkapp.com",
    "sparkpostmail.com",
    "mandrillapp.com",
    "exacttarget.com", "sfmc-content.com",
    "eloqua.com",
    "marketo.com", "mktocdn.com", "mktoweb.com",
    "hubspot.com", "hubspotlinks.com", "hs-analytics.net",
    "pardot.com",
    "sailthru.com",
    "braze.com",
    "iterable.com",
    "klaviyo.com",
    "omnisend.com",
    "getresponse.com",
    "aweber.com",
    "convertkit.com",
    "drip.com",
    "activecampaign.com",
    "moosend.com",
    "sendinblue.com", "brevo.com",
    "mailjet.com",
    # Analytics
    "google-analytics.com",
    "doubleclick.net",
    "googlesyndication.com",
    "googletagmanager.com",
    "facebook.com/tr",
    "px.ads.linkedin.com",
    "bat.bing.com",
    "analytics.twitter.com",
    "t.co",
    "click.redditmail.com",
}

# =============================================================================
# Known Authentication/SSO Domains
# =============================================================================

AUTH_DOMAINS = {
    # OAuth/SSO providers
    "login.microsoftonline.com",
    "login.live.com",
    "accounts.google.com",
    "appleid.apple.com",
    "auth0.com",
    "okta.com",
    "onelogin.com",
    "ping.com", "pingidentity.com",
    "duo.com",
    "login.salesforce.com",
    "github.com/login",
    "gitlab.com/users/sign_in",
    "bitbucket.org/account/signin",
}

# =============================================================================
# Legitimate Brand Domains
# =============================================================================

LEGITIMATE_BRAND_DOMAINS = {
    "microsoft": [
        "microsoft.com", "office.com", "outlook.com", "live.com",
        "hotmail.com", "azure.com", "windows.com", "xbox.com",
        "linkedin.com", "github.com", "visualstudio.com",
        "microsoftonline.com", "office365.com", "sharepoint.com",
        "onedrive.com", "skype.com", "bing.com", "msn.com",
    ],
    "google": [
        "google.com", "gmail.com", "youtube.com", "android.com",
        "chromium.org", "googleplex.com", "googlemail.com",
        "google.co.uk", "google.de", "google.fr", "google.es",
        "google.ca", "google.com.au", "google.co.in", "google.co.jp",
        "googleapis.com", "gstatic.com", "googleusercontent.com",
    ],
    "apple": [
        "apple.com", "icloud.com", "me.com", "mac.com",
        "apple.co.uk", "apple.de", "apple.fr",
        "itunes.com", "appstore.com",
    ],
    "amazon": [
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
        "amazon.ca", "amazon.com.au", "amazon.co.jp", "amazon.in",
        "aws.amazon.com", "amazonaws.com", "amzn.com", "amzn.to",
        "a]prime video.com", "audible.com", "goodreads.com",
        "whole foods market.com", "twitch.tv",
    ],
    "paypal": [
        "paypal.com", "paypal.me", "paypal.co.uk", "paypal.de",
        "paypal.fr", "paypalobjects.com",
    ],
    "facebook": [
        "facebook.com", "fb.com", "fb.me", "messenger.com",
        "instagram.com", "whatsapp.com", "meta.com",
        "oculus.com", "workplace.com", "fbcdn.net",
    ],
    "netflix": [
        "netflix.com", "nflxvideo.net", "nflximg.net",
        "nflxext.com", "nflxso.net",
    ],
    "twitter": [
        "twitter.com", "x.com", "t.co", "twimg.com",
    ],
    "linkedin": [
        "linkedin.com", "lnkd.in", "licdn.com",
    ],
    "openai": [
        "openai.com", "chatgpt.com", "chat.openai.com",
        "platform.openai.com", "api.openai.com",
    ],
    "anthropic": [
        "anthropic.com", "claude.ai",
    ],
    "dropbox": [
        "dropbox.com", "dropboxapi.com", "dropboxusercontent.com",
    ],
    "docusign": [
        "docusign.com", "docusign.net",
    ],
    "zoom": [
        "zoom.us", "zoom.com", "zoomgov.com",
    ],
    "slack": [
        "slack.com", "slack-edge.com", "slack-msgs.com",
    ],
}

# Build reverse lookup: domain -> brand
DOMAIN_TO_BRAND = {}
for brand, domains in LEGITIMATE_BRAND_DOMAINS.items():
    for domain in domains:
        DOMAIN_TO_BRAND[domain.lower()] = brand

# =============================================================================
# Suspicious TLDs (NOT including common legitimate TLDs like .com)
# =============================================================================

SUSPICIOUS_TLDS = {
    # Frequently abused newer TLDs
    ".xyz", ".top", ".work", ".click", ".link",
    ".online", ".site", ".website", ".space",
    ".live", ".icu", ".buzz", ".rest",
    ".monster", ".quest", ".cam", ".loan",
    ".zip", ".mov",  # Confusing with file extensions
    # Country codes frequently abused
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free Freenom TLDs
    ".cc", ".ws", ".su",
}

# =============================================================================
# Commonly Impersonated Brands
# =============================================================================

IMPERSONATED_BRANDS = {
    "paypal", "amazon", "microsoft", "apple", "google", "facebook",
    "netflix", "bank", "wells fargo", "chase", "citi", "hsbc", "barclays",
    "dropbox", "docusign", "linkedin", "twitter", "instagram",
    "dhl", "fedex", "ups", "usps", "royal mail",
    "irs", "hmrc", "social security",
    "openai", "chatgpt", "anthropic", "claude",
    "zoom", "slack", "teams",
}

# =============================================================================
# Unsubscribe patterns
# =============================================================================

UNSUBSCRIBE_PATTERNS = [
    r"unsubscribe",
    r"opt[\-_]?out",
    r"remove[\-_]?me",
    r"email[\-_]?preferences",
    r"manage[\-_]?subscriptions?",
    r"notification[\-_]?settings?",
]
