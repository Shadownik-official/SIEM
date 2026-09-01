import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { Sidebar } from '@/components/Sidebar'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'SIEM Dashboard',
  description: 'Comprehensive Security Information and Event Management Tool',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={`${inter.className} flex bg-gray-100`}>
        <Sidebar />
        <main className="flex-grow p-8 ml-64 overflow-y-auto">
          {children}
        </main>
      </body>
    </html>
  )
}
