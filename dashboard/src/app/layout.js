import "./globals.css";

export const metadata = {
  title: "Invecto Compliance Guard | Multi-Framework Security Dashboard",
  description: "Enterprise compliance auditing platform — CIS Benchmarks, NIST 800-53, CSA CCM, container security (Docker/Kubernetes), and live cloud scanning for AWS, Azure & GCP. Powered by Cisco Sec-8B.",
  keywords: ["CIS", "NIST", "CCM", "compliance", "cloud security", "container security", "docker", "kubernetes", "AWS", "Azure", "GCP", "terraform", "invecto", "cisco", "sec-8b"],
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var theme = localStorage.getItem('theme') || 'light';
                  document.documentElement.setAttribute('data-theme', theme);
                } catch (e) {}
              })();
            `,
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
