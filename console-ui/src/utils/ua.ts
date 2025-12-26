export function isMobileUserAgent(ua: string): boolean {
  const t = ua.toLowerCase();
  return (
    t.includes("iphone") ||
    t.includes("ipad") ||
    t.includes("ipod") ||
    t.includes("android") ||
    t.includes("mobile") ||
    t.includes("windows phone")
  );
}

