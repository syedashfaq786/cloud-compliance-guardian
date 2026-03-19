import "./globals.css";

export const metadata = {
  title: "Cloud Compliance Guardian | Security Dashboard",
  description: "AI-powered Terraform CIS Benchmark compliance monitoring dashboard — powered by Cisco Sec-8B",
  keywords: ["terraform", "CIS", "compliance", "security", "dashboard", "cisco", "sec-8b"],
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
