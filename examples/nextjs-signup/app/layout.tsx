export const metadata = { title: "doorkeep + Next.js" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui", maxWidth: 420, margin: "10vh auto", padding: 16 }}>{children}</body>
    </html>
  );
}
