import './globals.css'
import { AuthProvider } from '@/components/providers/AuthProvider'

export const metadata = {
  title: 'SIEM Dashboard',
  description: 'Enterprise Security Information and Event Management Dashboard',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  )
}