import { headers } from 'next/headers'

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const headerStore = await headers()
  const nonce = headerStore.get('x-nonce') || undefined

  return (
    <html lang="en">
      <body nonce={nonce}>{children}</body>
    </html>
  )
}
