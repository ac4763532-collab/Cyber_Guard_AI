/**
 * CyberGuard AI — SEO & Metadata Component
 * ============================================================================
 * Manages unique page titles, meta descriptions, canonical URLs,
 * Open Graph metadata, and Twitter Card tags per view dynamically.
 */

import { useEffect } from "react";
import { useLocation } from "react-router-dom";

export interface SEOProps {
  title: string;
  description?: string;
  canonicalPath?: string;
  ogImage?: string;
  ogType?: "website" | "article";
  structuredData?: Record<string, any>;
}

export function SEO({
  title,
  description = "CyberGuard AI is an autonomous, multi-agent cybersecurity platform delivering real-time endpoint telemetry, threat detection, verified SOC investigations, and organizational incident response.",
  canonicalPath,
  ogImage = "/og-image.svg",
  ogType = "website",
  structuredData,
}: SEOProps) {
  const location = useLocation();
  const origin = typeof window !== "undefined" ? window.location.origin : "https://cyberguard-api-7z5k.onrender.com";
  const canonicalUrl = `${origin}${canonicalPath || location.pathname}`;
  const fullTitle = title.includes("CyberGuard") ? title : `${title} | CyberGuard AI`;

  useEffect(() => {
    // 1. Set document title
    document.title = fullTitle;

    // Helper to set or create meta tag
    const setMetaTag = (attribute: "name" | "property", key: string, content: string) => {
      let element = document.querySelector(`meta[${attribute}="${key}"]`);
      if (!element) {
        element = document.createElement("meta");
        element.setAttribute(attribute, key);
        document.head.appendChild(element);
      }
      element.setAttribute("content", content);
    };

    // 2. Standard Meta Tags
    setMetaTag("name", "description", description);
    setMetaTag("name", "robots", "index, follow");

    // 3. Open Graph Tags
    setMetaTag("property", "og:title", fullTitle);
    setMetaTag("property", "og:description", description);
    setMetaTag("property", "og:type", ogType);
    setMetaTag("property", "og:url", canonicalUrl);
    setMetaTag("property", "og:image", `${origin}${ogImage}`);
    setMetaTag("property", "og:site_name", "CyberGuard AI");

    // 4. Twitter Card Tags
    setMetaTag("name", "twitter:card", "summary_large_image");
    setMetaTag("name", "twitter:title", fullTitle);
    setMetaTag("name", "twitter:description", description);
    setMetaTag("name", "twitter:image", `${origin}${ogImage}`);

    // 5. Canonical Link
    let canonicalLink = document.querySelector<HTMLLinkElement>("link[rel='canonical']");
    if (!canonicalLink) {
      canonicalLink = document.createElement("link");
      canonicalLink.setAttribute("rel", "canonical");
      document.head.appendChild(canonicalLink);
    }
    canonicalLink.setAttribute("href", canonicalUrl);

    // 6. Structured Data Injection
    let scriptTag = document.getElementById("page-structured-data") as HTMLScriptElement | null;
    if (structuredData) {
      if (!scriptTag) {
        scriptTag = document.createElement("script");
        scriptTag.id = "page-structured-data";
        scriptTag.type = "application/ld+json";
        document.head.appendChild(scriptTag);
      }
      scriptTag.textContent = JSON.stringify(structuredData);
    } else if (scriptTag) {
      scriptTag.remove();
    }
  }, [fullTitle, description, canonicalUrl, ogImage, ogType, origin, structuredData]);

  return null;
}

export default SEO;
